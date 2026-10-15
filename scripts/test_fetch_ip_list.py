#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_ip_list.py 单元测试
========================
覆盖：条目解析校验（IP/CIDR/注释/去重/IPv4 过滤）、Redis SET 写入（桩客户端）、
键名白名单。纯标准库 unittest。

运行(在 novawaf/scripts 目录):
    python3 -m unittest test_fetch_ip_list -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fetch_ip_list as fl  # noqa: E402


class FakeRedis:
    """记录式桩客户端：模拟 DEL/SADD/SCARD 行为。"""

    def __init__(self):
        self.commands = []
        self.store = set()

    def cmd(self, *args):
        self.commands.append(args)
        op = args[0]
        if op == "DEL":
            self.store.clear()
            return 1
        if op == "SADD":
            # args = ("SADD", key, *members)：跳过命令与键名
            before = len(self.store)
            self.store.update(args[2:])
            return len(self.store) - before
        if op == "SCARD":
            return len(self.store)
        raise AssertionError("未预期的命令: %r" % (args,))


class ParseEntriesTests(unittest.TestCase):

    def test_accepts_ip_and_cidr(self):
        entries, total = fl.parse_entries("1.2.3.4\n10.0.0.0/24\n192.168.1.7/31\n")
        self.assertEqual(entries, ["1.2.3.4", "10.0.0.0/24", "192.168.1.7/31"])
        self.assertEqual(total, 3)

    def test_keeps_original_text_not_normalized(self):
        # 与后端导入路径一致：仅校验合法性，保留原文（host bits 不归一、单 IP 不补 /32）
        entries, _ = fl.parse_entries("10.0.0.7/8\n1.2.3.4\n1.2.3.4/32\n")
        self.assertEqual(entries, ["10.0.0.7/8", "1.2.3.4", "1.2.3.4/32"])

    def test_skips_comments_and_blank_and_garbage(self):
        text = "# head\n\n1.2.3.4\nnot-an-ip\n999.1.1.1\n1.2.3.4/33\n:end\n"
        entries, total = fl.parse_entries(text)
        self.assertEqual(entries, ["1.2.3.4"])
        self.assertEqual(total, 5)  # 计数不含注释/空行

    def test_dedup_keeps_first_occurrence_order(self):
        entries, _ = fl.parse_entries("1.2.3.4\n5.6.7.8\n1.2.3.4\n")
        self.assertEqual(entries, ["1.2.3.4", "5.6.7.8"])

    def test_filters_ipv6(self):
        entries, total = fl.parse_entries("2001:db8::/32\n1.2.3.4\n")
        self.assertEqual(entries, ["1.2.3.4"])
        self.assertEqual(total, 2)

    def test_empty_result(self):
        entries, total = fl.parse_entries("# nothing valid\n")
        self.assertEqual(entries, [])
        self.assertEqual(total, 0)


class WriteRedisTests(unittest.TestCase):

    def test_write_replaces_and_batches(self):
        cli = FakeRedis()
        cli.store.add("9.9.9.9")  # 预置旧数据，write_redis 应先 DEL
        entries = ["1.2.3.4"] * 3  # 重复项在 SET 中只算 1 条
        entries += ["10.0.0.%d/32" % i for i in range(10)]
        n = fl.write_redis(cli, "novawaf:ipgroup:1", entries)
        self.assertEqual(n, 11)
        self.assertEqual(cli.commands[0][0], "DEL")  # 整体替换语义
        sadd_calls = [c for c in cli.commands if c[0] == "SADD"]
        # 11 个唯一条目 < SADD_BATCH(5000)，单批写入
        self.assertEqual(len(sadd_calls), 1)

    def test_batching(self):
        cli = FakeRedis()
        entries = ["10.1.%d.%d" % (i // 256, i % 256) for i in range(12000)]
        fl.write_redis(cli, "novawaf:ipgroup:2", entries)
        sadd_calls = [c for c in cli.commands if c[0] == "SADD"]
        self.assertEqual(len(sadd_calls), 3)  # 5000 + 5000 + 2000
        self.assertEqual(int(cli.cmd("SCARD")), 12000)


class KeyGuardTests(unittest.TestCase):

    def test_key_pattern(self):
        self.assertTrue(fl.KEY_RE.match("novawaf:ipgroup:1"))
        self.assertTrue(fl.KEY_RE.match("novawaf:ipgroup:1234567890"))
        for bad in ("novawaf:ipgroup:", "novawaf:ipgroup:abc", "novawaf:deploy:nat",
                    "novawaf:ioc", "novawaf:ipgroup:1:x", "", "novawaf:ipgroup:-1"):
            self.assertIsNone(fl.KEY_RE.match(bad), bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
