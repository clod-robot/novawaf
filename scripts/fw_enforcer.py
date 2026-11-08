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
  NOVA_FW_FLOOD       洪泛协议限速联动开关 1/0（默认 1，仅 nft 后端生效）
  NOVA_FW_FLOOD_HOLD  判定恢复后维持限速的秒数（默认 60，防抖）
"""
import ipaddress
import json
import os
import re
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
# 洪泛联动：引擎每秒写 novawaf:fw:flood:verdict（自适应判定结果），
# 本进程据此下发"按源限速"（nft meter，非全局一刀切），并把精确 pps 回写
# novawaf:fw:flood:counters 供引擎识别 /proc 无法区分的 ACK/DNS 洪泛。
VERDICT_KEY = "novawaf:fw:flood:verdict"
COUNTER_KEY = "novawaf:fw:flood:counters"
FLOOD_ENABLE = os.getenv("NOVA_FW_FLOOD", "1") == "1"
FLOOD_HOLD = int(os.getenv("NOVA_FW_FLOOD_HOLD", "60"))   # 判定恢复后维持限速的秒数（防抖）


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
        # 复测 P1：封禁期黑洞——DROP 让 SYN 静默丢弃，客户端只能等 8s+ 超时。
        # 改 REJECT：TCP 立即回 RST（快速失败），其余协议回 ICMP 不可达。
        # 两条规则：TCP 专用 tcp-reset，兜底通用 reject。
        if self.kind == "iptables":
            # 已存在则跳过（-C 检查），避免重复
            if not run("iptables", "-C", "NOVAWAF", "-s", ip, "-p", "tcp",
                       "-j", "REJECT", "--reject-with", "tcp-reset"):
                run("iptables", "-I", "NOVAWAF", "1", "-s", ip, "-p", "tcp",
                    "-j", "REJECT", "--reject-with", "tcp-reset")
            if not run("iptables", "-C", "NOVAWAF", "-s", ip, "-j", "REJECT"):
                run("iptables", "-I", "NOVAWAF", "2", "-s", ip, "-j", "REJECT")
        elif self.kind == "nft":
            run("nft", "add", "rule", "inet", "novawaf", "input",
                f"ip saddr {ip} meta l4proto tcp reject with tcp reset")
            run("nft", "add", "rule", "inet", "novawaf", "input",
                f"ip saddr {ip} reject")

    def unban(self, ip):
        if self.kind == "iptables":
            run("iptables", "-D", "NOVAWAF", "-s", ip, "-p", "tcp",
                "-j", "REJECT", "--reject-with", "tcp-reset")
            run("iptables", "-D", "NOVAWAF", "-s", ip, "-j", "REJECT")
        elif self.kind == "nft":
            # nft 无按内容删除的简便命令，先 flush 重建链（量小可接受）
            pass  # 见 sweep：nft 下用整链 flush 后重建

    def flush(self):
        if self.kind == "iptables":
            run("iptables", "-F", "NOVAWAF")
        elif self.kind == "nft":
            run("nft", "flush", "chain", "inet", "novawaf", "input")

    # ---------------- 洪泛防护（仅 nft 后端；iptables 无 meter，退化为不受理） ----------------
    FLOOD_COUNTER_RULES = [
        ("icmp", "meta l4proto icmp"),
        ("syn",  "meta l4proto tcp tcp flags syn"),
        ("ack",  "meta l4proto tcp tcp flags & (syn|ack) == ack"),
        ("udp",  "meta l4proto udp"),
        ("dns",  "meta l4proto udp udp dport 53"),
    ]
    # 按源限速（meter 动态集合）：单源超限才丢，正常客户端不受影响。
    FLOOD_LIMITS = {
        "ICMPFLOOD": ("meta l4proto icmp", "120/second", "240"),
        "SYNFLOOD":  ("meta l4proto tcp tcp flags syn", "120/second", "240"),
        "ACKFLOOD":  ("meta l4proto tcp tcp flags & (syn|ack) == ack", "120/second", "240"),
        "UDPFLOOD":  ("meta l4proto udp", "600/second", "1200"),
        "DNSFLOOD":  ("meta l4proto udp udp dport 53", "240/second", "480"),
        "HTTPFLOOD": ("meta l4proto tcp ct state new", "80/second", "160"),
    }

    def setup_flood(self):
        """建独立计数链（priority -200，最先看到包）与限速链（priority -150）。"""
        if self.kind != "nft":
            return
        run("nft", "add", "table", "inet", "novawaf")
        run("nft", "add", "chain", "inet", "novawaf", "floodcnt",
            "{ type filter hook input priority -200; }")
        run("nft", "add", "chain", "inet", "novawaf", "flood",
            "{ type filter hook input priority -150; }")
        # 计数链只在初始化时构建一次：规则顺序固定，读取按 comment 匹配不受顺序影响
        run("nft", "flush", "chain", "inet", "novawaf", "floodcnt")
        for name, match in self.FLOOD_COUNTER_RULES:
            run("nft", "add", "rule", "inet", "novawaf", "floodcnt",
                f"{match} counter comment \"flood_{name}\"")

    def read_flood_counters(self):
        """返回 {icmp: packets, syn:..., ack:..., udp:..., dns:...}；失败返回 {}。"""
        if self.kind != "nft":
            return {}
        try:
            r = subprocess.run(["nft", "list", "chain", "inet", "novawaf", "floodcnt"],
                               capture_output=True, text=True, timeout=5)
        except Exception:
            return {}
        if r.returncode != 0:
            return {}
        out = {}
        for line in r.stdout.splitlines():
            m = re.search(r"\bcounter packets (\d+)", line)
            if not m:
                continue
            c = re.search(r'comment "flood_(\w+)"', line)
            if c:
                out[c.group(1)] = int(m.group(1))
        return out

    def apply_flood(self, kind):
        """按判定结果重建限速链（幂等）：kind=None 表示解除。"""
        if self.kind != "nft":
            return
        run("nft", "flush", "chain", "inet", "novawaf", "flood")
        if not kind:
            return
        spec = self.FLOOD_LIMITS.get(kind)
        if not spec:
            return
        _match, rate, burst = spec
        # meter 按源分桶：size 65535 覆盖典型僵尸网络规模，超限源整包丢弃
        run("nft", "add", "rule", "inet", "novawaf", "flood",
            f"meter flood_{kind.lower()} {{ ip saddr limit rate over {rate} burst {burst} packets }} "
            f"drop comment \"flood_mit_{kind.lower()}\"")
        print(f"[fw] FLOOD mitigation on kind={kind} rate={rate}", flush=True)


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
    fw.setup_flood()
    print(f"[fw] started backend={fw.kind} ttl={TTL}s whitelist={WHITELIST} flood={FLOOD_ENABLE}", flush=True)

    bans = {}  # ip -> expire_ts
    r = None
    last_sweep = time.time()
    # 洪泛联动状态
    last_cnt_at = 0.0
    prev_cnt = {}
    active_kind = None          # 当前已下发的限速类型
    clear_since = 0.0           # 判定恢复的时刻（用于 FLOOD_HOLD 防抖）
    syncookies_on = False
    while True:
        try:
            if r is None:
                r = Redis(REDIS_HOST, REDIS_PORT, REDIS_PASS, REDIS_DB)
            item = r.cmd("BLPOP", QUEUE, "1")
        except Exception as e:
            print(f"[fw] redis error, reconnect: {e}", file=sys.stderr)
            time.sleep(3); r = None; continue
        if item:
            payload = item[1] if isinstance(item, list) and len(item) > 1 else None
            if payload:
                # 载荷：ip|ts|category|ruleId|count|ttl —— ttl 由引擎信誉模型计算
                # （首封 × 2^(n-1)，封顶 2×信誉半衰期，破"解封即再封"死循环）；
                # 旧版载荷无 ttl 字段则回退环境变量 TTL。
                parts = payload.split("|")
                ip = parts[0]
                ttl = TTL
                if len(parts) >= 6:
                    try:
                        ttl = max(10, min(int(parts[5]), 86400))
                    except ValueError:
                        pass
                if not is_whitelisted(ip) and ip not in bans:
                    fw.ban(ip)
                    bans[ip] = time.time() + ttl
                    print(f"[fw] BAN {ip} reason={payload} ttl={ttl}s", flush=True)

        # ---- 洪泛：每秒采样 nft 计数 → 回写 pps；消费引擎判定 → 下发按源限速 ----
        now = time.time()
        if FLOOD_ENABLE and fw.kind == "nft" and now - last_cnt_at >= 1.0:
            dt = now - last_cnt_at if last_cnt_at else 1.0
            last_cnt_at = now
            cur = fw.read_flood_counters()
            pps = {}
            if cur:
                for k, v in cur.items():
                    pps[k] = max(0.0, (v - prev_cnt.get(k, v)) / dt)
                prev_cnt = cur
            try:
                if cur:
                    r.cmd("SET", COUNTER_KEY, json.dumps({
                        "ts": int(now), "icmp": round(pps.get("icmp", 0), 1),
                        "syn": round(pps.get("syn", 0), 1), "ack": round(pps.get("ack", 0), 1),
                        "udp": round(pps.get("udp", 0), 1), "dns": round(pps.get("dns", 0), 1),
                    }))
                # 判定：level>=2 才下发，恢复后维持 FLOOD_HOLD 秒（防抖）
                vraw = r.cmd("GET", VERDICT_KEY)
                v = json.loads(vraw) if vraw else {}
                stale = (not v) or (now - float(v.get("ts", 0)) > 10)
                lvl = 0 if stale else int(v.get("level", 0))
                kind = None if stale else v.get("kind")
                if lvl >= 2 and kind in fw.FLOOD_LIMITS:
                    if active_kind != kind:
                        fw.apply_flood(kind)
                        active_kind = kind
                    clear_since = 0.0
                    # SYN 洪泛兜底：确认内核开启 syncookies（半开队列溢出时仍可建连）
                    if kind == "SYNFLOOD" and not syncookies_on:
                        subprocess.run(["sysctl", "-w", "net.ipv4.tcp_syncookies=1"],
                                       capture_output=True, timeout=5)
                        syncookies_on = True
                else:
                    if active_kind and clear_since == 0.0:
                        clear_since = now
                    if active_kind and clear_since and now - clear_since > FLOOD_HOLD:
                        fw.apply_flood(None)
                        print(f"[fw] FLOOD mitigation cleared (was {active_kind})", flush=True)
                        active_kind = None
                        clear_since = 0.0
            except Exception as e:
                print(f"[fw] flood bridge error: {e}", file=sys.stderr)
                r = None

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
