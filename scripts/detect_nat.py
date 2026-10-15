#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NovaWAF 部署网络类型(NAT)探测脚本
=================================

用途
----
在客户内网部署环境中自动判定 WAF 入口前置设备的 NAT/代理模式，并明确回答：
"当前部署能否识别外网真实源 IP？"

判定结果 natType:
  - DNAT    : 前置设备做目的地址转换(端口映射/透明转发)，源地址保留，可识别真实源 IP
  - L7_XFF  : 前置七层代理注入 X-Forwarded-For，可识别(需可信代理配置正确)
  - SNAT    : 前置设备做源地址改写且无可用 XFF，应用层无法还原真实源 IP
  - UNKNOWN : 证据不足(无流量样本/无权限)，需补采后复测

接入方式
--------
1. 管理后台一键触发(admin-server 以固定 argv 调起本脚本)；
2. 离线执行并写 Redis:  python3 detect_nat.py --write-redis
   结果写入 novawaf:deploy:nat，控制台只读展示。

安全设计
--------
- 仅做只读探测：不修改系统网络/防火墙配置；
- 调用 iptables/nft 等外部命令一律使用固定 argv(不经过 shell)，带超时；
- 文件读取设大小上限；Redis 为自写 RESP(无第三方依赖、无 redis-cli 依赖)；
- 不输出任何口令/敏感环境变量。

仅依赖 Python 3.8+ 标准库。
"""

import argparse
import glob
import gzip
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime

# ----------------------------- 阈值与常量 -----------------------------

MIN_SAMPLES = 20          # 参与判定所需的最小访问样本数
DIVERSE_PUBLIC = 5        # "多样公网 IP" 的去重阈值
PUBLIC_RATIO = 0.70       # DNAT: 公网来源占比阈值
CONC_RATIO = 0.80         # SNAT/L7: 来源汇聚(前 3 个地址合计)占比阈值
MAX_CONC_ADDRS = 3        # 汇聚判定允许的固定地址个数
READ_CAP = 2 * 1024 * 1024   # 单个日志/配置文件最多读取 2MiB
EXEC_TIMEOUT = 5          # 外部命令超时(秒)
ENGINE_ACCESS_LIMIT = 2000   # 从 novawaf:access 取尾部多少条做引擎侧证

NAT_REDIS_KEY = "novawaf:deploy:nat"

NGINX_LOG_DIRS = ("/usr/local/nginx/logs", "/var/log/nginx")
NGINX_CONF_DIRS = ("/usr/local/nginx/conf", "/etc/nginx")
LOG_NAME_HINTS = ("access.log", "access_log")

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# combined 日志: 首 token 为 $remote_addr
LOG_HEAD_RE = re.compile(r"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+\"([^\"]*)\"\s+(\d{3})\s+(\S+)")
QUOTED_RE = re.compile(r'"([^"]*)"')
XFF_TOKENS = ("$http_x_forwarded_for", "$proxy_add_x_forwarded_for",
              "$realip_remote_addr", "$http_x_real_ip")


# ----------------------------- IP 工具 -----------------------------

def is_public_ip(ip):
    """公网单播 IPv4/IPv6 判定；私网/环回/链路本地/保留/多播/未指定均视为非公网。"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def valid_ip(ip):
    try:
        ipaddress.ip_address((ip or "").strip())
        return True
    except ValueError:
        return False


def first_xff_ip(xff):
    """从 X-Forwarded-For 串中取最左侧(原始客户端)的合法 IP；无则返回 None。"""
    if not xff or xff == "-":
        return None
    for part in xff.split(","):
        cand = part.strip().lower()
        # 个别实现带端口/前缀名，仅截取纯 IP 段
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", cand)
        token = m.group(1) if m else cand
        if valid_ip(token):
            return token
    return None


# ----------------------------- /proc 解析 -----------------------------

def parse_route(content):
    """解析 /proc/net/route，返回默认网关(十六进制小端 -> 点分)。"""
    gateway = None
    for line in content.splitlines()[1:]:
        f = line.split()
        if len(f) < 3:
            continue
        try:
            dest = int(f[1], 16)
            gw = int(f[2], 16)
        except ValueError:
            continue
        if dest == 0 and gw:
            gateway = "%d.%d.%d.%d" % (gw & 0xff, (gw >> 8) & 0xff,
                                       (gw >> 16) & 0xff, (gw >> 24) & 0xff)
            break
    return gateway


def parse_fib_trie(content):
    """解析 /proc/net/fib_trie，提取标记为 host LOCAL 的本机地址集合。"""
    addrs = set()
    prev_ip = None
    for line in content.splitlines():
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})/\d+", line)
        if m:
            prev_ip = m.group(1)
            continue
        if prev_ip and "host LOCAL" in line:
            addrs.add(prev_ip)
        if not line.strip().startswith(("|", " ")):
            prev_ip = None
    return addrs


def read_text_capped(path, cap=READ_CAP):
    """只读文件尾部最多 cap 字节(大日志安全)；二进制/异常返回 ""。"""
    try:
        with open(path, "rb") as fh:
            if cap and os.fstat(fh.fileno()).st_size > cap:
                fh.seek(-cap, os.SEEK_END)
                fh.readline()  # 丢弃可能被截断的半行
            data = fh.read(cap + 1)
        return data.decode("utf-8", "replace")
    except OSError:
        return ""


def read_gzip_capped(path, cap=READ_CAP):
    """读取 gzip 日志解压后的尾部最多 cap 字节。"""
    tail = b""
    try:
        with gzip.open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                tail += chunk
                if len(tail) > cap:
                    tail = tail[-cap:]
    except (OSError, EOFError, gzip.BadGzipFile):
        return ""
    return tail.decode("utf-8", "replace")


# ----------------------------- nginx 侧证据(主证据) -----------------------------

def parse_log_line(line):
    """
    解析一行访问日志 -> {"remote": ip, "xff": ip|None}
    要求至少是 combined 形态(首 token 为 $remote_addr)；XFF 取末尾“纯 IP 列表”引号字段。
    """
    m = LOG_HEAD_RE.match(line)
    if not m:
        return None
    remote = m.group(1)
    if not IP_RE.match(remote) or not valid_ip(remote):
        return None
    xff = None
    for field in QUOTED_RE.findall(line):
        f = field.strip()
        # 仅接受“纯 IP 列表”形态(允许逗号/空格/冒号)；含字母或斜杠的是 request/UA/Referer，跳过
        if not f or f == "-" or re.search(r"[A-Za-z/()<>;]", f):
            continue
        if re.fullmatch(r"[\d.,:\s]*\d{1,3}(?:\.\d{1,3}){3}[\d.,:\s]*", f):
            xff = first_xff_ip(f)
    return {"remote": remote, "xff": xff}


def parse_log_text(text):
    samples = []
    for line in text.splitlines():
        rec = parse_log_line(line)
        if rec:
            samples.append(rec)
    return samples


def discover_log_files(explicit=()):
    files = []
    for p in explicit:
        files.extend(sorted(glob.glob(p)))
    seen = set(files)
    for d in NGINX_LOG_DIRS:
        for name in ("access.log", "access.log.1"):
            p = os.path.join(d, name)
            if p not in seen and os.path.isfile(p):
                seen.add(p)
                files.append(p)
        for p in sorted(glob.glob(os.path.join(d, "*.access.log"))) + \
                sorted(glob.glob(os.path.join(d, "access.log.*.gz"))):
            if p not in seen:
                seen.add(p)
                files.append(p)
    return files


def collect_nginx_samples(explicit=()):
    samples = []
    files = discover_log_files(explicit)
    for p in files:
        text = read_gzip_capped(p) if p.endswith(".gz") else read_text_capped(p)
        samples.extend(parse_log_text(text))
    return samples, files


def scan_nginx_xff_config():
    """扫描 nginx 配置，判断 log_format 是否记录 XFF(取证能力)。"""
    recorded = False
    hit_conf = None
    for d in NGINX_CONF_DIRS:
        for p in sorted(glob.glob(os.path.join(d, "**", "*.conf"), recursive=True))[:200]:
            text = read_text_capped(p, cap=512 * 1024)
            if "log_format" in text and any(tok in text for tok in XFF_TOKENS):
                recorded = True
                hit_conf = p
                break
        if recorded:
            break
    return recorded, hit_conf


# ----------------------------- 本机 NAT 规则侧证 -----------------------------

def _safe_cmd(argv):
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=EXEC_TIMEOUT, check=False)
        return proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""


def scan_local_nat_rules():
    """只读查看本机 iptables/nft nat 规则(存在与否仅作侧证)。"""
    ev = {"iptablesDnat": 0, "iptablesSnatOrMasq": 0, "nftDnat": 0,
          "nftSnatOrMasq": 0, "available": False}
    out = _safe_cmd(["iptables", "-t", "nat", "-S"])
    if not out:
        out = _safe_cmd(["iptables-nft", "-t", "nat", "-S"])
    if out:
        ev["available"] = True
        for line in out.splitlines():
            if "-j DNAT" in line:
                ev["iptablesDnat"] += 1
            if "-j SNAT" in line or "-j MASQUERADE" in line:
                ev["iptablesSnatOrMasq"] += 1
    nft = _safe_cmd(["nft", "list", "ruleset"])
    if nft:
        ev["available"] = True
        for line in nft.splitlines():
            low = line.lower()
            if "dnat to" in low:
                ev["nftDnat"] += 1
            if "snat to" in low or "masquerade" in low:
                ev["nftSnatOrMasq"] += 1
    return ev


# ----------------------------- 可信代理自检 -----------------------------

def scan_trusted_proxies():
    """读取 novawaf-engine 进程环境中的 NOVA_TRUSTED_PROXIES(不输出其它环境变量)。"""
    found = set()
    for cmdline_path in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            with open(cmdline_path, "rb") as fh:
                cmdline = fh.read(2048)
        except OSError:
            continue
        if b"novawaf-engine" not in cmdline:
            continue
        env_path = os.path.join(os.path.dirname(cmdline_path), "environ")
        try:
            with open(env_path, "rb") as fh:
                env = fh.read(8192)
        except OSError:
            continue
        for item in env.split(b"\x00"):
            if item.startswith(b"NOVA_TRUSTED_PROXIES="):
                val = item.split(b"=", 1)[1].decode("utf-8", "replace")
                for part in val.replace(";", ",").split(","):
                    part = part.strip()
                    if part:
                        found.add(part)
    return sorted(found)


# ----------------------------- 极简 RESP 客户端 -----------------------------

class RedisError(Exception):
    pass


class RedisSimple:
    """仅覆盖本脚本所需: PING/AUTH/SELECT/SET/GET/KEYS/LRANGE；自写 RESP，无第三方依赖。"""

    def __init__(self, host="127.0.0.1", port=6379, password="", db=0, timeout=3):
        self.host = host
        self.port = int(port)
        self.password = password or ""
        self.db = int(db)
        self.timeout = timeout
        self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        if self.password:
            self.cmd("AUTH", self.password)
        if self.db:
            self.cmd("SELECT", str(self.db))

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
        self.sock.recv(2)  # CRLF
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

    def set_json(self, key, obj):
        return self.cmd("SET", key, json.dumps(obj, ensure_ascii=False))

    def get_json(self, key):
        raw = self.cmd("GET", key)
        if not raw:
            return None
        return json.loads(raw)


def collect_engine_evidence(r):
    """
    引擎侧证：引擎记录的 clientIp 是否已是多样公网 IP。
    r 为 RedisSimple 或 None(连不上时跳过)。
    """
    ev = {"available": False, "sampleCount": 0, "uniqueSources": 0,
          "publicUnique": 0, "seesRealIp": False, "error": None}
    if r is None:
        return ev, []
    try:
        ips = []
        try:
            keys = r.cmd("KEYS", "novawaf:traffic:stat:*") or []
            for k in keys:
                try:
                    stat = r.get_json(k) or {}
                except (ValueError, RedisError):
                    continue
                cur = stat.get("cur") if isinstance(stat, dict) else None
                bucket = cur.get("ip") if isinstance(cur, dict) else None
                if isinstance(bucket, list):
                    ips.extend(str(x) for x in bucket)
        except RedisError:
            pass
        try:
            rows = r.cmd("LRANGE", "novawaf:access", -ENGINE_ACCESS_LIMIT, -1) or []
            for row in rows:
                try:
                    m = json.loads(row)
                except ValueError:
                    continue
                if isinstance(m, dict):
                    for kf in ("ip", "clientIp", "cip", "remote"):
                        if m.get(kf):
                            ips.append(str(m[kf]))
                            break
        except RedisError:
            pass
        ev["available"] = True
        ev["sampleCount"] = len(ips)
        ev["uniqueSources"] = len(set(ips))
        ev["publicUnique"] = len({x for x in ips if is_public_ip(x)})
        ev["seesRealIp"] = ev["publicUnique"] >= DIVERSE_PUBLIC
    except Exception as e:  # 侧证失败不影响主判定
        ev["error"] = str(e)[:200]
    return ev, []


# ----------------------------- 核心判定(可注入数据, 便于单测) -----------------------------

def classify(samples, min_samples=MIN_SAMPLES):
    """
    依据访问样本(remote/xff)统计判定 NAT 类型。
    返回 (natType, 统计证据 dict)。
    """
    total = len(samples)
    remotes = [s["remote"] for s in samples]
    xff_public = [s["xff"] for s in samples if s.get("xff") and is_public_ip(s["xff"])]
    remote_public = [ip for ip in remotes if is_public_ip(ip)]

    rc = Counter(remotes)
    top_list = rc.most_common(MAX_CONC_ADDRS)
    top_conc = sum(n for _, n in top_list)
    unique = len(rc)
    public_unique = len(set(remote_public))
    xff_public_unique = len(set(xff_public))

    stats = {
        "sampleCount": total,
        "uniqueSources": unique,
        "publicUnique": public_unique,
        "concentratedAddrs": [a for a, _ in top_list],
        "concentratedRatio": round(top_conc / total, 3) if total else 0.0,
        "publicRatio": round(len(remote_public) / total, 3) if total else 0.0,
        "xffPublicUnique": xff_public_unique,
    }

    if total < min_samples:
        return "UNKNOWN", stats

    # 1) 来源本身即多样公网 -> DNAT(源保留)
    if public_unique >= DIVERSE_PUBLIC and stats["publicRatio"] >= PUBLIC_RATIO:
        return "DNAT", stats

    # 2) 来源汇聚为少数固定地址, 但 XFF 最左跳为多样公网 -> L7 代理注入 XFF
    if (stats["concentratedRatio"] >= CONC_RATIO
            and xff_public_unique >= DIVERSE_PUBLIC):
        return "L7_XFF", stats

    # 3) 来源汇聚为少数固定地址且无可用 XFF -> SNAT/源改写
    if (stats["concentratedRatio"] >= CONC_RATIO
            and public_unique < DIVERSE_PUBLIC
            and xff_public_unique < DIVERSE_PUBLIC):
        return "SNAT", stats

    return "UNKNOWN", stats


# ----------------------------- 结论文案 -----------------------------

_TITLE = {
    "DNAT": "当前为 DNAT 端口映射/透明转发(源地址保留)，可识别外网真实源 IP",
    "L7_XFF": "前置为七层代理并注入 X-Forwarded-For，可识别外网真实源 IP(依赖可信代理配置)",
    "SNAT": "前置为 SNAT/源地址改写且无可用 X-Forwarded-For，无法识别外网真实源 IP",
    "UNKNOWN": "证据不足，暂无法判定 NAT 类型",
}

_STEPS = {
    "DNAT": [
        "保持前置设备的 DNAT/透明转发模式，不要在入向链路上叠加 SNAT。",
        "若 nginx 与引擎同机回环代理，引擎环境变量 NOVA_TRUSTED_PROXIES 应包含 127.0.0.1。",
        "不要无条件信任客户端自带的 XFF，防止伪造源 IP 绕过(仅信任前置代理跳数)。",
    ],
    "L7_XFF": [
        "确认网关会覆盖(而非追加)外部请求自带的 X-Forwarded-For，防止客户端伪造。",
        "在 nginx log_format 中记录 $http_x_forwarded_for，满足审计取证(等保)要求。",
        "引擎侧 NOVA_TRUSTED_PROXIES 仅配置该网关的内网地址(最小化信任)，整改后重新检测。",
    ],
    "SNAT": [
        "在前置网关/防火墙上对入向流量关闭 SNAT/源地址转换，或改用 DNAT 端口映射(保留源地址)。",
        "若网关仅支持七层代理：开启 X-Forwarded-For 注入，nginx 记录 XFF，引擎设置 NOVA_TRUSTED_PROXIES=<网关内网IP>。",
        "整改后重新运行本脚本(或在控制台点击“重新检测”)复测。",
    ],
    "UNKNOWN": [
        "先确认站点已有真实外部访问流量(样本不足时无法判定)，再重新检测。",
        "在 nginx log_format 末尾追加 \"$http_x_forwarded_for\" 字段，以区分 SNAT 与七层代理。",
        "也可在服务器离线执行: python3 detect_nat.py --write-redis，结果将同步到控制台。",
    ],
}


def build_advice(nat_type, evidence, trusted, engine_ev):
    tips = []
    proxy = evidence.get("concentratedAddrs", [None])[0] if evidence.get("concentratedAddrs") else None
    if nat_type == "L7_XFF":
        if trusted:
            if proxy and proxy not in trusted:
                tips.append("汇聚代理地址 %s 不在 NOVA_TRUSTED_PROXIES=%s 中，引擎可能取不到真实 IP，请补齐可信代理配置。"
                            % (proxy, ",".join(trusted)))
        else:
            tips.append("未检测到引擎的 NOVA_TRUSTED_PROXIES 配置，XFF 可能不被采信。")
        if engine_ev.get("available") and not engine_ev.get("seesRealIp"):
            tips.append("引擎当前记录到的公网源地址不足 %d 个，XFF→引擎链路疑似未贯通。" % DIVERSE_PUBLIC)
        if engine_ev.get("available") and engine_ev.get("seesRealIp"):
            tips.append("引擎已记录到多样公网源 IP，XFF 可信链路实测贯通。")
    if nat_type == "SNAT":
        tips.append("应用层已丢失真实源地址，仅能在前置设备侧整改，WAF/主机侧无法还原。")
    if nat_type == "DNAT" and trusted:
        tips.append("本机可信代理: %s(仅在确有本机代理跳数时保留)。" % ",".join(trusted))
    if nat_type == "UNKNOWN" and evidence.get("localDnatRules"):
        tips.append("本机 iptables/nft 存在 DNAT 规则，但缺少足够流量样本确认实际入向链路。")
    return " ".join(tips) if tips else _TITLE[nat_type].split("，", 1)[-1]


# ----------------------------- 主流程 -----------------------------

def detect(redis_client=None, explicit_logs=()):
    gateway = parse_route(read_text_capped("/proc/net/route"))
    local_addrs = sorted(parse_fib_trie(read_text_capped("/proc/net/fib_trie")))
    trusted = scan_trusted_proxies()
    nginx_xff_recorded, xff_conf = scan_nginx_xff_config()
    nat_rules = scan_local_nat_rules()

    nginx_samples, log_files = collect_nginx_samples(explicit_logs)
    nat_type, stats = classify(nginx_samples)
    evidence_source = "nginx"

    engine_ev, _ = collect_engine_evidence(redis_client)

    # nginx 无样本时，退回引擎记录做侧证判定
    if nat_type == "UNKNOWN" and stats["sampleCount"] < MIN_SAMPLES and engine_ev.get("available"):
        # 引擎侧仅有 clientIp 维度：多样公网=DNAT/L7 已生效；汇聚且无公网=疑似 SNAT
        if engine_ev.get("seesRealIp"):
            nat_type, evidence_source = "DNAT", "engine"
        elif engine_ev.get("sampleCount", 0) >= MIN_SAMPLES:
            nat_type, evidence_source = "SNAT", "engine"

    can_identify = nat_type in ("DNAT", "L7_XFF")
    evidence = {
        "source": evidence_source,
        "gateway": gateway,
        "localAddr": ",".join(local_addrs) if local_addrs else None,
        "nginxLogFiles": log_files,
        "nginxRecordXff": nginx_xff_recorded,
        "nginxXffConf": xff_conf,
        "trustedProxies": trusted,
        "localDnatRules": nat_rules.get("iptablesDnat", 0) + nat_rules.get("nftDnat", 0),
        "localSnatRules": nat_rules.get("iptablesSnatOrMasq", 0) + nat_rules.get("nftSnatOrMasq", 0),
    }
    evidence.update(stats)
    if engine_ev.get("available"):
        evidence["engineClientIpSamples"] = engine_ev.get("sampleCount")
        evidence["enginePublicUnique"] = engine_ev.get("publicUnique")
        evidence["engineSeesRealIp"] = engine_ev.get("seesRealIp")
    if engine_ev.get("error"):
        evidence["engineError"] = engine_ev["error"]

    result = {
        "natType": nat_type,
        "canIdentifyExternalIp": can_identify,
        "title": _TITLE[nat_type],
        "advice": build_advice(nat_type, evidence, trusted, engine_ev),
        "evidence": evidence,
        "steps": _STEPS[nat_type],
        "generatedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description="NovaWAF 部署网络类型(NAT)探测")
    ap.add_argument("--write-redis", action="store_true", help="把结果写入 Redis novawaf:deploy:nat")
    ap.add_argument("--redis-host", default=os.environ.get("NOVA_REDIS_HOST", "127.0.0.1"))
    ap.add_argument("--redis-port", type=int, default=int(os.environ.get("NOVA_REDIS_PORT", "6379")))
    ap.add_argument("--redis-password", default=os.environ.get("NOVA_REDIS_PASSWORD", ""))
    ap.add_argument("--redis-db", type=int, default=int(os.environ.get("NOVA_REDIS_DB", "0")))
    ap.add_argument("--logs", action="append", default=[], help="显式指定 access.log 路径(可多次)")
    ap.add_argument("--out", default="", help="同时把 JSON 结果写入指定文件")
    args = ap.parse_args(argv)

    client = None
    if args.write_redis:
        try:
            client = RedisSimple(args.redis_host, args.redis_port,
                                 args.redis_password, args.redis_db)
            client.connect()
        except (OSError, RedisError) as e:
            print(json.dumps({"fatal": "无法连接 Redis: %s" % str(e)[:200]},
                             ensure_ascii=False), file=sys.stderr)
            return 2

    try:
        result = detect(client, explicit_logs=args.logs)
    except Exception as e:  # 探测本身不应致命中断，兜底输出 UNKNOWN
        result = {
            "natType": "UNKNOWN", "canIdentifyExternalIp": False,
            "title": _TITLE["UNKNOWN"],
            "advice": "探测过程发生异常: %s" % str(e)[:200],
            "evidence": {"error": str(e)[:500]},
            "steps": _STEPS["UNKNOWN"],
            "generatedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        }

    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as e:
            print("写结果文件失败: %s" % e, file=sys.stderr)

    if args.write_redis:
        try:
            client.set_json(NAT_REDIS_KEY, result)
        except RedisError as e:
            print("写 Redis 失败: %s" % str(e)[:200], file=sys.stderr)
            return 2
        finally:
            client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
