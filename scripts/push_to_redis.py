#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
push_to_redis.py — 将 NovaWAF 数据文件推入 Redis，供引擎内存加载，免除磁盘 IO。

零依赖实现：纯标准库 socket + RESP 协议（服务器无 redis-py / 无 sudo 时可用）。

Redis 数据布局:
  novawaf:geoip      STRING  -> geoip.txt 全文（引擎 loadFromLines 按行切分）
  novawaf:ioc        STRING  -> ioc.txt 全文
  novawaf:meta       HASH    -> geoip_cksum / ioc_cksum / updated_at（供引擎判断是否需重载）

用法:
  python3 push_to_redis.py --geoip engine/rules/geoip.txt --ioc engine/rules/ioc.txt
  python3 push_to_redis.py --host 127.0.0.1 --port 6379 --pass xxx --db 0 ...
  # 仅推一个文件:
  python3 push_to_redis.py --ioc engine/rules/ioc.txt

设计（等保/性能）:
  * 与 Redis 通信为内网明文，仅绑定 127.0.0.1 / 受信网段；生产应加 --pass + 防火墙。
  * 写入用 cksum 判等，内容未变则不写，避免无意义刷新与缓存失效。
  * 元信息 updated_at 便于审计与排障。
"""
import argparse
import hashlib
import os
import socket
import sys
import time


class RespClient:
    """极简 RESP 客户端：仅实现本脚本需要的命令。"""

    def __init__(self, host, port, password=None, db=0, timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        if password:
            self.execute("AUTH", password)
        if db:
            self.execute("SELECT", str(db))

    def _read_line(self):
        while b"\r\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("redis closed connection")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("redis closed connection")
            self.buf += chunk
        data = self.buf[:n]
        self.buf = self.buf[n + 2:]  # 吃掉尾随 \r\n
        return data

    def _read_reply(self):
        line = self._read_line()
        prefix = line[:1]
        if prefix == b"+":
            return line[1:].decode()
        if prefix == b"-":
            raise RuntimeError("redis error: " + line[1:].decode())
        if prefix == b":":
            return int(line[1:])
        if prefix == b"$":
            n = int(line[1:])
            if n == -1:
                return None
            return self._read_exact(n)
        if prefix == b"*":
            n = int(line[1:])
            if n == -1:
                return None
            return [self._read_reply() for _ in range(n)]
        raise RuntimeError("unknown resp prefix: " + repr(prefix))

    def execute(self, *args):
        parts = []
        for a in args:
            if isinstance(a, str):
                a = a.encode()
            parts.append(b"$" + str(len(a)).encode() + b"\r\n" + a + b"\r\n")
        cmd = b"*" + str(len(args)).encode() + b"\r\n" + b"".join(parts)
        self.sock.sendall(cmd)
        return self._read_reply()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def cksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def push_file(cli, key, label, path):
    if not path or not os.path.exists(path):
        print(f"  [{label}] skip (missing): {path}", file=sys.stderr)
        return False
    with open(path, "rb") as f:
        data = f.read()
    cur = cli.execute("GET", key)
    cs = cksum(data)
    if cur is not None and cksum(cur) == cs:
        print(f"  [{label}] unchanged (cksum {cs}), skip write", file=sys.stderr)
        return False
    cli.execute("SET", key, data)
    cli.execute("HSET", "novawaf:meta", f"{label}_cksum", cs,
                f"{label}_updated", str(int(time.time())))
    size_kb = len(data) / 1024.0
    lines = data.count(b"\n")
    print(f"  [{label}] pushed -> {key} ({size_kb:.1f} KB, {lines} lines, cksum {cs})",
          file=sys.stderr)
    return True


def main():
    ap = argparse.ArgumentParser(description="Push NovaWAF data files into Redis")
    ap.add_argument("--host", default=os.environ.get("REDIS_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("REDIS_PORT", "6379")))
    ap.add_argument("--pass", dest="password", default=os.environ.get("REDIS_PASS"))
    ap.add_argument("--db", type=int, default=0)
    ap.add_argument("--geoip", help="path to geoip.txt")
    ap.add_argument("--ioc", help="path to ioc.txt")
    args = ap.parse_args()

    if not args.geoip and not args.ioc:
        ap.error("nothing to push: give --geoip and/or --ioc")

    cli = RespClient(args.host, args.port, args.password, args.db)
    pong = cli.execute("PING")
    print(f"redis {args.host}:{args.db} -> {pong}", file=sys.stderr)

    changed = False
    changed |= push_file(cli, "novawaf:geoip", "geoip", args.geoip)
    changed |= push_file(cli, "novawaf:ioc", "ioc", args.ioc)
    print("done. changed=" + str(changed), file=sys.stderr)
    cli.close()


if __name__ == "__main__":
    main()
