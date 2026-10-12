#!/usr/bin/env python3
"""NovaWAF 防火墙联动执行器（防外部端口/连接攻击）。

消费 Redis 队列 novawaf:fw:ban（引擎投递的攻击源 IP），下发到 Linux netfilter
做 L3/L4 封禁，并在 TTL 到期后自动解封。与引擎解耦：引擎不持 root、不操作防火墙。

后端优先级：nftables > iptables（Ubuntu 22.04+ 的 iptables 多为 nft 后端，二选一即可）。
所有规则放在独立链/表 novawaf 中，便于隔离与清理，不污染用户既有规则。

环境变量：
  NOVA_REDIS_HOST/PORT/PASS/DB
  NOVA_FW_BAN_TTL     封禁时长秒（默认 3600）
  NOVA_FW_WHITELIST   永不封禁的 IP/CIDR 逗号列表（默认 127.0.0.1,::1）
  NOVA_FW_SWEEP       解封扫描间隔秒（默认 30）
"""
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import time

REDIS_HOST = os.getenv("NOVA_REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("NOVA_REDIS_PORT", "6379"))
REDIS_PASS = os.getenv("NOVA_REDIS_PASS", "")
REDIS_DB = int(os.getenv("NOVA_REDIS_DB", "0"))
QUEUE = "novawaf:fw:ban"
TTL = int(os.getenv("NOVA_FW_BAN_TTL", "3600"))
SWEEP = int(os.getenv("NOVA_FW_SWEEP", "30"))
WHITELIST = [x.strip() for x in os.getenv("NOVA_FW_WHITELIST", "127.0.0.1,::1").split(",") if x.strip()]


class Redis:
    def __init__(self, host, port, passwd="", db=0, timeout=5):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""
        if passwd: self.cmd("AUTH", passwd)
        if db: self.cmd("SELECT", str(db))

    def _send(self, args):
        out = f"*{len(args)}\r\n".encode()
        for a in args:
            a = a.encode() if isinstance(a, str) else a
            out += f"${len(a)}\r\n".encode() + a + b"\r\n"
        self.s.sendall(out)

    def _line(self):
        while b"\r\n" not in self.buf:
            ch = self.s.recv(4096)
            if not ch: raise ConnectionError("redis closed")
            self.buf += ch
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _read(self):
        line = self._line(); t = line[0:1]
        if t == b"+": return line[1:].decode()
        if t == b"-": raise RuntimeError(line[1:].decode())
        if t == b":": return int(line[1:])
        if t == b"$":
            n = int(line[1:])
            if n < 0: return None
            while len(self.buf) < n + 2: self.buf += self.s.recv(4096)
            data = self.buf[:n]; self.buf = self.buf[n + 2:]
            return data.decode()
        if t == b"*":
            n = int(line[1:]); return [self._read() for _ in range(n)]
        raise RuntimeError("bad resp")

    def cmd(self, *a):
        self._send(list(a)); return self._read()


def run(*args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=8)
        return r.returncode == 0
    except Exception as e:
        print(f"[fw] cmd failed {args}: {e}", file=sys.stderr)
        return False


class FwBackend:
    def __init__(self):
        self.kind = None
        if shutil.which("nft"):
            self.kind = "nft"
        elif shutil.which("iptables"):
            self.kind = "iptables"

    def setup(self):
        if self.kind == "iptables":
            # 独立链 NOVAWAF，挂到 INPUT 顶部；已存在则忽略错误
            run("iptables", "-N", "NOVAWAF")
            run("iptables", "-I", "INPUT", "1", "-j", "NOVAWAF")
        elif self.kind == "nft":
            run("nft", "add", "table", "inet", "novawaf")
            run("nft", "add", "chain", "inet", "novawaf", "input",
                "{ type filter hook input priority -100; }")

    def ban(self, ip):
        if self.kind == "iptables":
            # 已存在则跳过（-C 检查），避免重复
            if not run("iptables", "-C", "NOVAWAF", "-s", ip, "-j", "DROP"):
                run("iptables", "-I", "NOVAWAF", "1", "-s", ip, "-j", "DROP")
        elif self.kind == "nft":
            run("nft", "add", "rule", "inet", "novawaf", "input",
                f"ip saddr {ip} drop")

    def unban(self, ip):
        if self.kind == "iptables":
            run("iptables", "-D", "NOVAWAF", "-s", ip, "-j", "DROP")
        elif self.kind == "nft":
            # nft 无按内容删除的简便命令，先 flush 重建链（量小可接受）
            pass  # 见 sweep：nft 下用整链 flush 后重建

    def flush(self):
        if self.kind == "iptables":
            run("iptables", "-F", "NOVAWAF")
        elif self.kind == "nft":
            run("nft", "flush", "chain", "inet", "novawaf", "input")


def is_whitelisted(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # 非法格式直接跳过，避免误操作
    if addr.is_loopback or addr.is_link_local:
        return True
    for w in WHITELIST:
        try:
            if "/" in w:
                if addr in ipaddress.ip_network(w, strict=False):
                    return True
            elif addr == ipaddress.ip_address(w):
                return True
        except ValueError:
            pass
    return False


def main():
    if os.geteuid() != 0:
        print("[fw] 警告：非 root 运行，iptables/nft 操作将失败。请以 root 启动本进程。", file=sys.stderr)
    fw = FwBackend()
    if not fw.kind:
        print("[fw] 未找到 nft 或 iptables，退出。", file=sys.stderr)
        sys.exit(1)
    fw.setup()
    print(f"[fw] started backend={fw.kind} ttl={TTL}s whitelist={WHITELIST}", flush=True)

    bans = {}  # ip -> expire_ts
    r = None
    last_sweep = time.time()
    while True:
        try:
            if r is None:
                r = Redis(REDIS_HOST, REDIS_PORT, REDIS_PASS, REDIS_DB)
            item = r.cmd("BLPOP", QUEUE, "3")
        except Exception as e:
            print(f"[fw] redis error, reconnect: {e}", file=sys.stderr)
            time.sleep(3); r = None; continue
        if item:
            payload = item[1] if isinstance(item, list) and len(item) > 1 else None
            if payload:
                ip = payload.split("|", 1)[0]
                if not is_whitelisted(ip) and ip not in bans:
                    fw.ban(ip)
                    bans[ip] = time.time() + TTL
                    print(f"[fw] BAN {ip} reason={payload} ttl={TTL}s", flush=True)

        # 定时解封过期 IP
        if time.time() - last_sweep >= SWEEP:
            last_sweep = time.time()
            now = time.time()
            expired = [ip for ip, exp in bans.items() if exp <= now]
            for ip in expired:
                fw.unban(ip); del bans[ip]
                print(f"[fw] UNBAN {ip} (expired)", flush=True)
            # nft 后端：整链 flush 后按当前有效集合重建（保证解封生效）
            if fw.kind == "nft" and expired:
                fw.flush()
                for ip in bans:
                    fw.ban(ip)


if __name__ == "__main__":
    main()
