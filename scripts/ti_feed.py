#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ti_feed.py — NovaWAF 威胁情报外部源订阅。

从授权来源（公开 IP 黑名单 / 自定义 URL / AbuseIPDB）拉取 IOC，
合并写入 Redis `novawaf:ioc`，引擎会按 `ioc_cksum` 在 60s 内热加载生效。

数据契约（与引擎 threat_intel + push_to_redis.py 一致）:
  novawaf:ioc   STRING  每行 "type,value,severity,category,desc"
  novawaf:meta  HASH    ioc_cksum (sha256[:16]) / ioc_updated (ts)

feed 维护的条目 category 以 "feed:" 开头，拉取时整体替换、不碰手动条目。

用法:
  python3 ti_feed.py                 # run-once（供 cron / systemd timer）
  python3 ti_feed.py --loop --interval 3600   # 守护模式，每小时一次
  python3 ti_feed.py --config feed.json        # 自定义来源配置
  ABUSEIPDB_API_KEY=xxx python3 ti_feed.py     # 启用 AbuseIPDB

合规: 仅拉取配置中授权的 URL；AbuseIPDB 遵守其接口约定；单源失败不影响整体。
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.request
import urllib.error

IOC_KEY = "novawaf:ioc"
META_KEY = "novawaf:meta"
FEED_PREFIX = "feed:"

# 默认公开免费 IP 黑名单（均可被 --config 覆盖）。仅在用户授权范围内使用。
DEFAULT_SOURCES = [
    {"name": "binarydefense", "url": "https://www.binarydefense.com/banlist.txt"},
    {"name": "firehol_level1",
     "url": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"},
]

IP_RE = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?')


# ---------------- 极简 RESP 客户端（零依赖，同 push_to_redis.py）----------------
class RespClient:
    def __init__(self, host, port, password=None, db=0, timeout=8.0):
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
                raise ConnectionError("redis closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("redis closed")
            self.buf += chunk
        data = self.buf[:n]
        self.buf = self.buf[n + 2:]
        return data

    def _read_reply(self):
        line = self._read_line()
        p = line[:1]
        if p == b"+":
            return line[1:].decode()
        if p == b"-":
            raise RuntimeError("redis error: " + line[1:].decode())
        if p == b":":
            return int(line[1:])
        if p == b"$":
            n = int(line[1:])
            return None if n == -1 else self._read_exact(n)
        if p == b"*":
            n = int(line[1:])
            return None if n == -1 else [self._read_reply() for _ in range(n)]
        raise RuntimeError("unknown resp prefix: " + repr(p))

    def execute(self, *args):
        parts = []
        for a in args:
            if isinstance(a, str):
                a = a.encode()
            parts.append(b"$" + str(len(a)).encode() + b"\r\n" + a + b"\r\n")
        self.sock.sendall(b"*" + str(len(args)).encode() + b"\r\n" + b"".join(parts))
        return self._read_reply()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def cksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def valid_ip(tok: str) -> bool:
    ip = tok.split("/")[0]
    try:
        parts = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    return len(parts) == 4 and all(0 <= p <= 255 for p in parts)


def is_excluded(tok: str) -> bool:
    """过滤私有/保留地址，避免情报污染误伤内网（RFC1918/回环/链路本地/CGNAT/组播/保留）。"""
    try:
        if "/" in tok:
            net = ipaddress.ip_network(tok, strict=False)
            return (net.is_private or net.is_loopback or net.is_link_local
                    or net.is_multicast or net.is_reserved or net.is_unspecified)
        ip = ipaddress.ip_address(tok)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return True  # 解析失败的一并丢弃


# ---------------- 拉取各来源 ----------------
def http_get(url: str, timeout: int, headers=None) -> str:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def parse_ips(text: str):
    """从文本提取 IPv4 / CIDR，返回 (ips_set, cidrs_set)。自动剔除私有/保留地址。"""
    ips, cidrs = set(), set()
    filtered = 0
    for m in IP_RE.findall(text):
        if not valid_ip(m):
            continue
        if is_excluded(m):
            filtered += 1
            continue
        if "/" in m:
            bits = int(m.split("/")[1])
            if 0 <= bits <= 32:
                cidrs.add(m)
        else:
            ips.add(m)
    if filtered:
        print(f"  [feed] filtered {filtered} private/reserved entries", file=sys.stderr)
    return ips, cidrs


def fetch_public_list(src: dict, timeout: int):
    try:
        text = http_get(src["url"], timeout)
    except Exception as e:
        print(f"  [feed] {src['name']} fetch failed: {e}", file=sys.stderr)
        return set(), set()
    ips, cidrs = parse_ips(text)
    print(f"  [feed] {src['name']}: +{len(ips)} ip +{len(cidrs)} cidr", file=sys.stderr)
    return ips, cidrs


def fetch_abuseipdb(key: str, confidence: int, timeout: int):
    """AbuseIPDB blacklist 接口（需 key）。遵守其限制，失败不抛。"""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    try:
        text = http_get(url, timeout, headers={
            "Key": key, "Accept": "application/json",
        })
        data = json.loads(text)
        ips = set()
        for item in data.get("data", []):
            ip = item.get("ipAddress")
            if ip and valid_ip(ip) and not is_excluded(ip):
                ips.add(ip)
        print(f"  [feed] abuseipdb: +{len(ips)} ip (conf>={confidence})", file=sys.stderr)
        return ips, set()
    except Exception as e:
        print(f"  [feed] abuseipdb failed (skipped): {e}", file=sys.stderr)
        return set(), set()


# ---------------- 合并写回 ----------------
def split_fields(line: str):
    return [f.strip() for f in line.split(",")]


def merge_and_write(cli, feed_ips, feed_cidrs, source_tag):
    cur = cli.execute("GET", IOC_KEY)
    cur_text = cur.decode("utf-8", "replace") if cur else ""

    kept = []  # 非 feed 条目（手动 + 注释）原样保留
    for line in cur_text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            kept.append(line)
            continue
        f = split_fields(line)
        category = f[3] if len(f) >= 4 else ""
        if not category.startswith(FEED_PREFIX):
            kept.append(line)

    # 生成新 feed 条目（去重）
    seen = set()
    new_lines = []
    def add(typ, value):
        k = f"{typ}:{value}"
        if k in seen:
            return
        seen.add(k)
        new_lines.append(f"{typ},{value},high,{source_tag},auto feed")
    for ip in sorted(feed_ips):
        add("ip", ip)
    for c in sorted(feed_cidrs):
        add("cidr", c)

    blob = ("\n".join(kept + new_lines) + "\n").encode("utf-8")
    cli.execute("SET", IOC_KEY, blob)
    cs = cksum(blob)
    cli.execute("HSET", META_KEY, "ioc_cksum", cs, "ioc_updated", str(int(time.time())))
    print(f"  [feed] wrote {len(new_lines)} feed entries (total {len(kept) + len(new_lines)} lines), cksum={cs}",
          file=sys.stderr)
    return len(new_lines)


def run_once(args, sources):
    cli = RespClient(args.host, args.port, args.password, args.db)
    all_ips, all_cidrs = set(), set()
    for src in sources:
        ips, cidrs = fetch_public_list(src, args.timeout)
        all_ips |= ips
        all_cidrs |= cidrs
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if key:
        ips, cidrs = fetch_abuseipdb(key, args.confidence, args.timeout)
        all_ips |= ips
        all_cidrs |= cidrs
    else:
        print("  [feed] abuseipdb skipped (no ABUSEIPDB_API_KEY)", file=sys.stderr)

    if not all_ips and not all_cidrs:
        print("  [feed] nothing fetched, skip write", file=sys.stderr)
        cli.close()
        return 0
    n = merge_and_write(cli, all_ips, all_cidrs, FEED_PREFIX + "external")
    cli.close()
    return n


def main():
    ap = argparse.ArgumentParser(description="NovaWAF threat intel feed puller")
    ap.add_argument("--host", default=os.environ.get("REDIS_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("REDIS_PORT", "6379")))
    ap.add_argument("--pass", dest="password", default=os.environ.get("REDIS_PASS"))
    ap.add_argument("--db", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--confidence", type=int, default=90, help="AbuseIPDB confidenceMinimum")
    ap.add_argument("--config", help="JSON config with 'sources' list [{name,url}] and 'custom_urls'")
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=3600)
    args = ap.parse_args()

    sources = list(DEFAULT_SOURCES)
    if args.config and os.path.exists(args.config):
        with open(args.config) as f:
            cfg = json.load(f)
        if "sources" in cfg:
            sources = cfg["sources"]
        for u in cfg.get("custom_urls", []):
            sources.append({"name": "custom", "url": u})

    if args.loop:
        print(f"[feed] loop mode, interval={args.interval}s", file=sys.stderr)
        while True:
            try:
                run_once(args, sources)
            except Exception as e:
                print(f"  [feed] cycle error: {e}", file=sys.stderr)
            time.sleep(args.interval)
    else:
        run_once(args, sources)


if __name__ == "__main__":
    main()
