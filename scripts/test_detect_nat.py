#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_nat.py 单元测试
======================
覆盖：DNAT / L7_XFF / SNAT / UNKNOWN 四类判定，以及 /proc 与 nginx 日志解析、
XFF 提取、端到端结果结构。纯标准库 unittest，无外部依赖。

运行(在 novawaf/scripts 目录):
    python3 -m unittest test_detect_nat -v
"""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect_nat as dn  # noqa: E402


def samples_dnat(n=30):
    """每笔来自不同公网 IP(源保留)。"""
    return [{"remote": "203.0.113.%d" % (i + 1), "xff": None} for i in range(n)]


def samples_l7_xff(n=30, proxy="10.0.0.1"):
    """nginx 只看到固定网关私网地址，XFF 最左跳为多样公网 IP。"""
    return [{"remote": proxy, "xff": "198.51.100.%d" % (i + 1)} for i in range(n)]


def samples_snat(n=30, gw="10.0.0.1"):
    """来源汇聚为固定地址且无 XFF。"""
    return [{"remote": gw, "xff": None} for _ in range(n)]


class ClassifyTests(unittest.TestCase):

    def test_dnat_when_diverse_public_remotes(self):
        nat_type, stats = dn.classify(samples_dnat())
        self.assertEqual(nat_type, "DNAT")
        self.assertGreaterEqual(stats["publicUnique"], dn.DIVERSE_PUBLIC)
        self.assertGreaterEqual(stats["publicRatio"], dn.PUBLIC_RATIO)

    def test_l7_xff_when_concentrated_remote_but_diverse_public_xff(self):
        nat_type, stats = dn.classify(samples_l7_xff())
        self.assertEqual(nat_type, "L7_XFF")
        self.assertGreaterEqual(stats["concentratedRatio"], dn.CONC_RATIO)
        self.assertGreaterEqual(stats["xffPublicUnique"], dn.DIVERSE_PUBLIC)

    def test_snat_when_concentrated_remote_without_xff(self):
        nat_type, stats = dn.classify(samples_snat())
        self.assertEqual(nat_type, "SNAT")
        self.assertLess(stats["xffPublicUnique"], dn.DIVERSE_PUBLIC)
        self.assertLess(stats["publicUnique"], dn.DIVERSE_PUBLIC)

    def test_unknown_when_samples_insufficient(self):
        nat_type, _ = dn.classify(samples_dnat(3))
        self.assertEqual(nat_type, "UNKNOWN")

    def test_unknown_when_mixed_inconclusive(self):
        # 来源既不汇聚、公网又不多样、XFF 也不足 -> 无法定论
        samples = [{"remote": "10.0.0.%d" % (i % 8 + 1), "xff": None} for i in range(40)]
        nat_type, _ = dn.classify(samples)
        self.assertEqual(nat_type, "UNKNOWN")

    def test_can_identify_mapping(self):
        # 与给客户的结论口径一致：仅 DNAT/L7_XFF 可识别
        self.assertTrue(dn._TITLE["DNAT"])
        self.assertIn("DNAT", dn.classify(samples_dnat())[0])
        self.assertEqual(dn.classify(samples_l7_xff())[0], "L7_XFF")
        self.assertEqual(dn.classify(samples_snat())[0], "SNAT")

    def test_min_samples_parameter_allows_small_fixtures(self):
        self.assertEqual(dn.classify(samples_snat(5), min_samples=5)[0], "SNAT")
        self.assertEqual(dn.classify(samples_snat(4), min_samples=5)[0], "UNKNOWN")


class IpTests(unittest.TestCase):

    def test_public_ip(self):
        for ip in ("203.0.113.1", "8.8.8.8", "1.1.1.1"):
            self.assertTrue(dn.is_public_ip(ip), ip)

    def test_private_ip(self):
        for ip in ("10.1.2.3", "172.16.5.4", "192.168.1.1", "127.0.0.1",
                   "169.254.1.1", "100.64.0.1", "", None):
            self.assertFalse(dn.is_public_ip(ip), repr(ip))

    def test_first_xff_leftmost(self):
        self.assertEqual(dn.first_xff_ip("203.0.113.9, 10.0.0.1"), "203.0.113.9")
        self.assertEqual(dn.first_xff_ip("198.51.100.7"), "198.51.100.7")
        self.assertIsNone(dn.first_xff_ip("-"))
        self.assertIsNone(dn.first_xff_ip(None))
        self.assertIsNone(dn.first_xff_ip("unknown"))


class ProcParseTests(unittest.TestCase):

    def test_parse_route_default_gw_little_endian(self):
        content = (
            "Iface\tDestination\tGateway\tFlags\tMTU\tWindow\tIRTT\n"
            "eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\n"
            "eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\n"
        )
        # 0x0100A8C0 小端 -> 192.168.0.1
        self.assertEqual(dn.parse_route(content), "192.168.0.1")

    def test_parse_route_no_default(self):
        content = "Iface\tDestination\tGateway\neth0\t0000A8C0\t00000000\n"
        self.assertIsNone(dn.parse_route(content))

    def test_parse_fib_trie_local_addrs(self):
        content = (
            "|-- 127.0.0.0\n"
            "   |-- 127.0.0.1\n"
            "      /32 host LOCAL\n"
            "|-- 192.168.100.2\n"
            "   /32 host LOCAL\n"
            "|-- 192.168.100.255\n"
            "   /32 link BROADCAST\n"
        )
        addrs = dn.parse_fib_trie(content)
        self.assertEqual(addrs, {"127.0.0.1", "192.168.100.2"})


class LogParseTests(unittest.TestCase):
    LINE = ('203.0.113.9 - - [14/Oct/2026:10:00:00 +0800] '
            '"GET / HTTP/1.1" 200 612 "-" "curl/8.4.0"')
    LINE_XFF = ('10.0.0.1 - - [14/Oct/2026:10:00:01 +0800] '
                '"GET /a HTTP/1.1" 200 10 "-" "python-requests/2.31" "203.0.113.9, 10.0.0.1"')

    def test_combined_without_xff(self):
        rec = dn.parse_log_line(self.LINE)
        self.assertEqual(rec, {"remote": "203.0.113.9", "xff": None})

    def test_combined_with_xff_list(self):
        rec = dn.parse_log_line(self.LINE_XFF)
        self.assertEqual(rec["remote"], "10.0.0.1")
        self.assertEqual(rec["xff"], "203.0.113.9")

    def test_bad_lines(self):
        self.assertIsNone(dn.parse_log_line(""))
        self.assertIsNone(dn.parse_log_line("not a log line"))
        self.assertIsNone(dn.parse_log_line('999.1.1.1 - - [x] "GET / HTTP/1.1" 200 1'))

    def test_parse_log_text_counts(self):
        text = "\n".join([self.LINE_XFF] * 25 + [self.LINE] * 5)
        samples = dn.parse_log_text(text)
        self.assertEqual(len(samples), 30)
        nat_type, stats = dn.classify(samples)
        self.assertEqual(nat_type, "L7_XFF")


class DetectEndToEndTests(unittest.TestCase):
    """用桩件替换真实系统读取，验证结果结构与 DNAT 文案组装。"""

    def _run_detect(self, samples):
        engine_ev = {"available": False, "sampleCount": 0, "uniqueSources": 0,
                     "publicUnique": 0, "seesRealIp": False, "error": None}
        with mock.patch.object(dn, "read_text_capped", return_value=""), \
             mock.patch.object(dn, "scan_trusted_proxies", return_value=["127.0.0.1"]), \
             mock.patch.object(dn, "scan_nginx_xff_config", return_value=(True, "/etc/nginx/nginx.conf")), \
             mock.patch.object(dn, "scan_local_nat_rules",
                               return_value={"iptablesDnat": 1, "iptablesSnatOrMasq": 0,
                                             "nftDnat": 0, "nftSnatOrMasq": 0, "available": True}), \
             mock.patch.object(dn, "collect_nginx_samples", return_value=(samples, ["/var/log/nginx/access.log"])), \
             mock.patch.object(dn, "collect_engine_evidence", return_value=(engine_ev, [])):
            return dn.detect(redis_client=None)

    def test_result_schema_dnat(self):
        result = self._run_detect(samples_dnat())
        for key in ("natType", "canIdentifyExternalIp", "title", "advice",
                    "evidence", "steps", "generatedAt"):
            self.assertIn(key, result)
        self.assertEqual(result["natType"], "DNAT")
        self.assertTrue(result["canIdentifyExternalIp"])
        self.assertEqual(result["evidence"]["source"], "nginx")
        self.assertEqual(result["evidence"]["localDnatRules"], 1)
        self.assertTrue(result["steps"])
        json.dumps(result, ensure_ascii=False)  # 必须可序列化供 Redis/接口使用

    def test_snat_flags_cannot_identify(self):
        result = self._run_detect(samples_snat())
        self.assertEqual(result["natType"], "SNAT")
        self.assertFalse(result["canIdentifyExternalIp"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
