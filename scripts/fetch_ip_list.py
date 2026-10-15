#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NovaWAF 自定义源 IP 列表拉取脚本
================================

供管理后台「IP 组 → 更新」调用（固定 argv，无 shell、有超时）：
    python3 fetch_ip_list.py --url https://example.com/iplist.txt \
        --write-redis-key novawaf:ipgroup:1

行为：
1. 拉取 URL 文本（TLS，超时/大小封顶，防 SSRF：仅允许 http/https 且禁用重定向到非 http(s)）；
2. 逐行校验（每行一个 IPv4/CIDR，# 与空行忽略），去重；
3. 写入 Redis SET（SADD，键来自 --write-redis-key，格式受白名单校验）；
4. stdout 输出 JSON {"written": N, "total": M}（条数用于后端日志/告警）。

安全设计：
- 不经 shell；Redis 连接参数读环境变量 NOVA_REDIS_HOST/PORT/PASS/DB（与 admin-server 一致）；
- 响应体大小封顶 32MB；单组条目上限由调用方（后端）把控；
- 键名白名单：仅允许 novawaf:ipgroup:<数字>，防止误写其它键。

仅依赖 Python 3.8+ 标准库。
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.request

MAX_BODY_BYTES = 32 * 1024 * 1024   # 32MB
FETCH_TIMEOUT = 20                  # 秒
KEY_RE = re.compile(r"^novawaf:ipgroup:\d{1,10}$")
SADD_BATCH = 5000


# ----------------------------- RESP（自写，无第三方依赖） -----------------------------

class RedisError(Exception):
    pass


class RedisSimple:
    """覆盖本脚本所需: AUTH/SELECT/DEL/SADD/SCARD。"""

    def __init__(self, host="127.0.0.1", port=6379, password="", db=0, timeout=5):
        self.host = host
        self.port = int(port)
        self.password = password or ""
        self.db = int(db)
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        if self.password:
            self.cmd("AUTH", self.password)
        if self.db:
            self.cmd("SELECT", str(self.db))
        return self

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.sock = None

    def cmd(self, *args):
        if self.sock is None:
            raise RedisError("redis 未连接")
        payload = b"*%d\r\n" % len(args)
        for a in args:
            b = str(a).encode("utf-8")
            payload += b"$%d\r\n%s\r\n" % (len(b), b)
        self.sock.sendall(payload)
        return self._read_reply()

    def _read_line(self):
        buf = bytearray()
        while not buf.endswith(b"\r\n"):
            ch = self.sock.recv(1)
            if not ch:
                raise RedisError("redis 连接已关闭")
            buf += ch
        return bytes(buf[:-2]).decode("utf-8", "replace")

    def _read_n(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise RedisError("redis 连接已关闭")
            data += chunk
        self.sock.recv(2)
        return data

    def _read_reply(self):
        prefix = self._read_line()
        t, body = prefix[0], prefix[1:]
        if t == "+":
            return body
        if t == "-":
            raise RedisError(body)
        if t == ":":
            return int(body)
        if t == "$":
            n = int(body)
            return None if n < 0 else self._read_n(n).decode("utf-8", "replace")
        if t == "*":
            n = int(body)
            return None if n < 0 else [self._read_reply() for _ in range(n)]
        raise RedisError("不支持的 RESP 类型: %r" % prefix)


# ----------------------------- 拉取与校验 -----------------------------

def fetch_text(url):
    """拉取文本并封顶 32MB；仅允许 http/https，不接受其它协议重定向。"""
    req = urllib.request.Request(url, headers={
        "User-Agent": "NovaWAF-fetch-ip-list/1.0",
        "Accept": "text/plain,*/*",
    })
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:  # noqa: S310 (仅 http/https)
        final = resp.geturl() or url
        if not final.lower().startswith(("http://", "https://")):
            raise ValueError("重定向到了非 http(s) 地址，已中止")
        data = resp.read(MAX_BODY_BYTES + 1)
    if len(data) > MAX_BODY_BYTES:
        raise ValueError("响应体超过 32MB 上限")
    return data.decode("utf-8", "replace")


def parse_entries(text):
    """逐行校验 IPv4/CIDR，去重保序；返回 (列表, 总行数)。
    仅做合法性校验，保留用户原文（与后端导入路径行为一致，不归一化改写）。"""
    uniq = dict()  # 有序去重
    total = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        total += 1
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue  # 引擎名单当前按 IPv4 处理
        uniq[s] = True
    return list(uniq), total


def write_redis(cli, key, entries):
    """DEL 后 SADD 分批写入，返回 SET 最终条数。"""
    cli.cmd("DEL", key)
    batch = []
    for e in entries:
        batch.append(e)
        if len(batch) >= SADD_BATCH:
            cli.cmd("SADD", key, *batch)
            batch = []
    if batch:
        cli.cmd("SADD", key, *batch)
    return int(cli.cmd("SCARD", key))


def main(argv=None):
    ap = argparse.ArgumentParser(description="NovaWAF 自定义源 IP 列表拉取")
    ap.add_argument("--url", required=True, help="http/https 文本源（每行 IPv4/CIDR）")
    ap.add_argument("--write-redis-key", required=True, help="目标 Redis SET 键（novawaf:ipgroup:<id>）")
    ap.add_argument("--keep", action="store_true", help="保留键中已有条目（默认整体替换）")
    args = ap.parse_args(argv)

    key = args.write_redis_key.strip()
    if not KEY_RE.match(key):
        print(json.dumps({"fatal": "非法的目标键: %s" % key}), file=sys.stderr)
        return 2

    try:
        text = fetch_text(args.url.strip())
    except Exception as e:
        print(json.dumps({"fatal": "拉取失败: %s" % str(e)[:200]}), file=sys.stderr)
        return 1

    entries, total = parse_entries(text)
    if not entries:
        print(json.dumps({"fatal": "源内容无有效 IPv4/CIDR 条目（共 %d 行）" % total}),
              file=sys.stderr)
        return 1

    host = os.environ.get("NOVA_REDIS_HOST", "127.0.0.1")
    port = int(os.environ.get("NOVA_REDIS_PORT", "6379"))
    password = os.environ.get("NOVA_REDIS_PASS", "")
    db = int(os.environ.get("NOVA_REDIS_DB", "0"))
    cli = None
    try:
        cli = RedisSimple(host, port, password, db).connect()
        if not args.keep:
            written = write_redis(cli, key, entries)
        else:
            for i in range(0, len(entries), SADD_BATCH):
                cli.cmd("SADD", key, *entries[i:i + SADD_BATCH])
            written = int(cli.cmd("SCARD", key))
        print(json.dumps({"written": written, "sourceLines": total, "key": key},
                         ensure_ascii=False))
        return 0
    except (OSError, RedisError) as e:
        print(json.dumps({"fatal": "写 Redis 失败: %s" % str(e)[:200]}), file=sys.stderr)
        return 2
    finally:
        if cli:
            cli.close()


if __name__ == "__main__":
    sys.exit(main())
