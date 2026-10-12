#!/usr/bin/env python3
"""NovaWAF 外部情报富集器（Phase 2）。

消费 Redis 队列 novawaf:intel:queue（引擎投递的文件 SHA-256），
异步查询 VirusTotal / OTX，把判定结果写回 novawaf:intel:hash:<sha>：
  "1" = 恶意, "0" = 干净/未知（均带 TTL，避免缓存无限膨胀）。

引擎侧首次见未知哈希时 fail-open 放行并投递；本脚本回写后，同哈希再次
上传即被引擎内存集命中拦截。全程不阻塞引擎热路径。

环境变量：
  NOVA_REDIS_HOST / NOVA_REDIS_PORT / NOVA_REDIS_PASS / NOVA_REDIS_DB
  NOVA_VT_APIKEY   VirusTotal API key（留空则跳过 VT）
  NOVA_OTX_APIKEY  OTX API key（留空则跳过 OTX）
  NOVA_INTEL_TTL   缓存 TTL 秒（默认 86400=1 天）
  NOVA_INTEL_VT_THROTTLE  VT 每次查询间隔秒（免费 key 限速，默认 16）
"""
import json
import os
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error

REDIS_HOST = os.getenv("NOVA_REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("NOVA_REDIS_PORT", "6379"))
REDIS_PASS = os.getenv("NOVA_REDIS_PASS", "")
REDIS_DB = int(os.getenv("NOVA_REDIS_DB", "0"))
QUEUE = "novawaf:intel:queue"
TTL = int(os.getenv("NOVA_INTEL_TTL", "86400"))
VT_THROTTLE = int(os.getenv("NOVA_INTEL_VT_THROTTLE", "16"))
VT_KEY = os.getenv("NOVA_VT_APIKEY", "")
OTX_KEY = os.getenv("NOVA_OTX_APIKEY", "")


# ---------- 零依赖 RESP Redis 客户端 ----------
class Redis:
    def __init__(self, host, port, passwd="", db=0, timeout=5):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""
        if passwd:
            self.cmd("AUTH", passwd)
        if db:
            self.cmd("SELECT", str(db))

    def _send(self, args):
        out = f"*{len(args)}\r\n".encode()
        for a in args:
            a = a.encode() if isinstance(a, str) else a
            out += f"${len(a)}\r\n".encode() + a + b"\r\n"
        self.s.sendall(out)

    def _read_line(self):
        while b"\r\n" not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise ConnectionError("redis closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _read(self):
        line = self._read_line()
        t = line[0:1]
        if t == b"+": return line[1:].decode()
        if t == b"-": raise RuntimeError(line[1:].decode())
        if t == b":": return int(line[1:])
        if t == b"$":
            n = int(line[1:])
            if n < 0: return None
            while len(self.buf) < n + 2:
                self.buf += self.s.recv(4096)
            data = self.buf[:n]
            self.buf = self.buf[n + 2:]
            return data.decode()
        if t == b"*":
            n = int(line[1:])
            return [self._read() for _ in range(n)]
        raise RuntimeError("bad resp: " + repr(line))

    def cmd(self, *args):
        self._send(list(args))
        return self._read()


def https_get(url, headers, timeout=8):
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read().decode("utf-8", "replace")


def query_vt(sha):
    """返回 True(恶意)/False(干净或未知)/None(查询失败)"""
    if not VT_KEY:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha}"
        body = https_get(url, {"x-apikey": VT_KEY, "Accept": "application/json"})
        data = json.loads(body)
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        return malicious > 0
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False  # VT 无记录 → 视为干净/未知
        return None
    except Exception as e:
        print(f"[vt] error {sha}: {e}", file=sys.stderr)
        return None


def query_otx(sha):
    if not OTX_KEY:
        return None
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{sha}/general"
        body = https_get(url, {"X-OTX-API-KEY": OTX_KEY, "Accept": "application/json"})
        data = json.loads(body)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        return len(pulses) > 0
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return None
    except Exception as e:
        print(f"[otx] error {sha}: {e}", file=sys.stderr)
        return None


def main():
    if not VT_KEY and not OTX_KEY:
        print("[enricher] 警告：未设置 NOVA_VT_APIKEY / NOVA_OTX_APIKEY，将只消费不入队判定。"
              "请配置 key 后重启本进程。", file=sys.stderr)
    r = Redis(REDIS_HOST, REDIS_PORT, REDIS_PASS, REDIS_DB)
    print(f"[enricher] started, consuming {QUEUE} (vt={'on' if VT_KEY else 'off'}, "
          f"otx={'on' if OTX_KEY else 'off'})", flush=True)
    while True:
        try:
            item = r.cmd("BLPOP", QUEUE, "5")
        except Exception as e:
            print(f"[enricher] redis error, reconnect: {e}", file=sys.stderr)
            time.sleep(3)
            try:
                r = Redis(REDIS_HOST, REDIS_PORT, REDIS_PASS, REDIS_DB)
            except Exception:
                time.sleep(3)
            continue
        if not item:
            continue
        sha = item[1] if isinstance(item, list) and len(item) > 1 else None
        if not sha or not (len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)):
            continue

        malicious = None
        # VT 优先（权威），限速；OTX 补充
        v = query_vt(sha)
        if VT_KEY:
            time.sleep(VT_THROTTLE)
        if v is not None:
            malicious = v
        else:
            o = query_otx(sha)
            if o is not None:
                malicious = o

        if malicious is None:
            # 都失败：不写缓存，下次再试
            print(f"[enricher] {sha}: 查询失败，跳过", flush=True)
            continue

        verdict = "1" if malicious else "0"
        try:
            r.cmd("SETEX", f"novawaf:intel:hash:{sha}", str(TTL), verdict)
            print(f"[enricher] {sha}: -> {'MALICIOUS' if malicious else 'clean'}", flush=True)
        except Exception as e:
            print(f"[enricher] write error {sha}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
