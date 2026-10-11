#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
maxmind_to_redis.py — MaxMind GeoLite2 Country CSV 一步到位：
    转换为 NovaWAF geoip.txt 格式，并直接写入 Redis，免除中间文件与磁盘 IO。

流程: MaxMind CSV → 内存转换(关联 geoname_id→国家) → 直接 SET 进 Redis
可选: 同时落一份本地 geoip.txt (-o) 作为备份/兜底。

输入 (GeoLite2-Country-CSV.zip 解压后):
  GeoLite2-Country-Blocks-IPv4.csv   network,geoname_id,registered_country_geoname_id,...
  GeoLite2-Country-Locations-en.csv  geoname_id,...,country_iso_code,country_name,...

Redis 布局 (与引擎 redis_client.h / loadDataLines 完全对应):
  novawaf:geoip      STRING  -> 转换后的全文（引擎按行切分）
  novawaf:meta       HASH    -> geoip_cksum / geoip_updated（判等，未变不写）

用法:
  # 只转 Redis（免 IO，推荐生产）
  python3 maxmind_to_redis.py --dir ./GeoLite2-Country-CSV_xxx

  # 转 Redis 并落本地备份
  python3 maxmind_to_redis.py --blocks x.csv --locations y.csv -o rules/geoip.txt

  # 指定 Redis
  python3 maxmind_to_redis.py --dir DIR --host 127.0.0.1 --port 6379 --pass xxx --db 0

零依赖实现：纯标准库 csv + socket + RESP（服务器无 redis-py / 无 sudo 也可用）。
安全：与 Redis 通信应走内网；生产须配密码 + 绑定受信地址（脚本支持 --pass）。
"""
import argparse
import csv
import hashlib
import ipaddress
import os
import socket
import sys
import time


# ---------------- RESP 客户端（零依赖） ----------------
class RespClient:
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
        self.buf = self.buf[n + 2:]
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


# ---------------- MaxMind 转换 ----------------
def detect_files(directory):
    blocks = loc = None
    for name in os.listdir(directory):
        low = name.lower()
        if low.startswith("geolite2-country-blocks-ipv4") and low.endswith(".csv"):
            blocks = os.path.join(directory, name)
        elif low.startswith("geolite2-country-locations-en") and low.endswith(".csv"):
            loc = os.path.join(directory, name)
    return blocks, loc


def build_country_index(locations_path):
    idx = {}
    with open(locations_path, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            gid = (row.get("geoname_id") or "").strip()
            iso = (row.get("country_iso_code") or "").strip().upper()
            name = (row.get("country_name") or "").strip()
            if not gid or not iso:
                continue
            idx[gid] = (iso, name)
    return idx


def _first(*vals):
    for v in vals:
        v = (v or "").strip()
        if v:
            return v
    return ""


def convert_to_text(blocks_path, locations_path):
    """返回 (text_bytes, range_count)。text 为引擎 geoip.txt 格式。"""
    idx = build_country_index(locations_path)
    if not idx:
        print("ERROR: empty country index from", locations_path, file=sys.stderr)
        sys.exit(2)

    seen = set()
    rows = []  # (start_int, cidr, iso, name)
    kept = skipped = 0
    with open(blocks_path, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            net = (row.get("network") or "").strip()
            if not net:
                continue
            gid = _first(row.get("geoname_id"),
                         row.get("registered_country_geoname_id"))
            cc = idx.get(gid)
            if cc is None:
                skipped += 1
                continue
            iso, name = cc
            try:
                netobj = ipaddress.ip_network(net, strict=False)
            except ValueError:
                skipped += 1
                continue
            start = int(netobj.network_address)
            key = (start, net)
            if key in seen:
                continue
            seen.add(key)
            rows.append((start, net, iso, name))
            kept += 1

    rows.sort(key=lambda r: r[0])
    out = []
    out.append("# NovaWAF geoip.txt — generated from MaxMind GeoLite2 Country CSV")
    out.append("# format: cidr,CC[,country_name]   (lines with # / blank ignored by engine)")
    out.append("# source: GeoLite2-Country-CSV  (offline; regenerate on each release)")
    out.append("")
    for _s, cidr, iso, name in rows:
        out.append(f"{cidr},{iso},{name}" if name else f"{cidr},{iso}")
    text = ("\n".join(out) + "\n").encode("utf-8")
    return text, kept, skipped


def cksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def push_to_redis(cli, key, meta_field, data, label):
    cur = cli.execute("GET", key)
    cs = cksum(data)
    if cur is not None and cksum(cur) == cs:
        print(f"  [{label}] unchanged (cksum {cs}), skip write", file=sys.stderr)
        return False
    cli.execute("SET", key, data)
    cli.execute("HSET", "novawaf:meta", f"{meta_field}_cksum", cs,
                f"{meta_field}_updated", str(int(time.time())))
    nl = data.count(b"\n")
    print(f"  [{label}] pushed -> {key} ({len(data)/1024:.1f} KB, {nl} lines, cksum {cs})",
          file=sys.stderr)
    return True


def main():
    ap = argparse.ArgumentParser(
        description="Convert MaxMind GeoLite2 CSV to NovaWAF format and write to Redis (no file IO)")
    ap.add_argument("--blocks", help="GeoLite2-Country-Blocks-IPv4.csv path")
    ap.add_argument("--locations", help="GeoLite2-Country-Locations-en.csv path")
    ap.add_argument("--dir", help="directory containing both CSVs (auto-detect)")
    ap.add_argument("-o", "--out", help="optional: also write local geoip.txt backup")
    ap.add_argument("--host", default=os.environ.get("REDIS_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("REDIS_PORT", "6379")))
    ap.add_argument("--pass", dest="password", default=os.environ.get("REDIS_PASS"))
    ap.add_argument("--db", type=int, default=0)
    ap.add_argument("--no-redis", action="store_true",
                    help="convert + write local file only, do not touch Redis")
    args = ap.parse_args()

    blocks, loc = args.blocks, args.locations
    if args.dir:
        b, l = detect_files(args.dir)
        blocks = blocks or b
        loc = loc or l
    if not blocks or not loc:
        ap.error("need --blocks and --locations (or --dir)")
    if not args.out and args.no_redis:
        ap.error("--no-redis requires -o to write a local file")

    text, kept, skipped = convert_to_text(blocks, loc)
    print(f"converted {kept} CIDR ranges (skipped {skipped} no-country rows)", file=sys.stderr)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "wb") as f:
            f.write(text)
        print(f"  [file] wrote backup -> {args.out}", file=sys.stderr)

    if not args.no_redis:
        cli = RespClient(args.host, args.port, args.password, args.db)
        pong = cli.execute("PING")
        print(f"redis {args.host}:{args.db} -> {pong}", file=sys.stderr)
        push_to_redis(cli, "novawaf:geoip", "geoip", text, "geoip")
        cli.close()
    print("done.", file=sys.stderr)


if __name__ == "__main__":
    main()
