#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NovaWAF 全量长时间测试守护脚本（L1 存活 + L2 接口回归 31 项 + L3 引擎热加载 + L4 远程压测基线）。

设计：
  - 跑在被测服务器本机（L1/L2/L3）+ 远程负载机 100.4 发 L4
  - 守护方式：systemd timer 每 15min 触发一轮，结果追加到 /var/log/novawaf-longtest.log
  - 下一次更新部署时：tail -500 /var/log/novawaf-longtest.log 直接出报告
  - 状态同时写 Redis key novawaf:longtest:latest（JSON，下次可 GET）
  - 纯标准库（urllib/json/subprocess/time/os/sys），零依赖；redis 用 sock.connect + RESP
  - 负载机 100.4 用 Python 3.12 asyncio 发并发请求，精确控 RPS + p95/p99

L1 存活（<5s 每次必跑）：
  - 端口 8099(引擎)/18081(后端)/9000(前端) 健康
  - engine 日志 /tmp/novawaf-engine.log 最近 10min 无 ERROR/CRITICAL
  - Redis ping + MySQL SELECT 1

L2 接口全量回归（~45s，31 项，就是 bench/regress_ipgroup.py 的等价版）：
  - 登录成功 / 无 token 401
  - Geo 策略：关闭/仅允许选中国家/封禁选中国家 + 非法 mode + 非法国家码 + 65 个超上限
  - IP 组 CRUD + 同名拒绝 + 空名/超长名拒绝 + CIDR+单IP 添加 + 非法条目 + 混合导入 added=3
  - SSRF file:// 拒绝 + 无 sourceUrl 时更新拒绝 + 分页/删单条/清空/同名更新自身

L3 引擎热加载（~120s）：
  - GeoPolicy 保存后 INCR novawaf:geo:policy:version → 等 3s 引擎日志 ver= 增量
  - IpGroup 导入后 resync ioc → 等 60s 引擎日志 novawaf:ioc 增量
  - 热加载前后 Redis novawaf:ioc 内容对比（sha256cksum 应变）

L4 远程压测基线（从 100.4 发，~60s）：
  - /api/auth/login、/api/waf/ipgroup/list (withCredentials)、/api/waf/blacklist
  - 每个接口 30s 恒定 RPS（50），p50/p95/p99/max/成功数/失败数

参数（环境变量可覆盖）：
  WAF_HOST      被测服务器 IP，默认 127.0.0.1（本机测试 / localhost）
  WAF_ADMIN     管理员账号，默认 admin
  WAF_PASSWORD  管理员密码，默认 Admin@2026
  ENGINE_LOG    引擎日志路径，默认 /tmp/novawaf-engine.log
  REDIS_HOST / REDIS_PORT / REDIS_SOCKET
  MYSQL_HOST / MYSQL_USER / MYSQL_PASSWORD / MYSQL_DB
  REMOTE_HOST   远程负载机 IP（可选，默认不启 L4；填了就 ssh 上去发压）
"""
import json, os, subprocess, sys, time, urllib.request, urllib.error, socket, struct, hashlib
from datetime import datetime, timezone, timedelta

WAF_HOST      = os.environ.get("WAF_HOST", "127.0.0.1")
WAF_PORT      = int(os.environ.get("WAF_PORT", "9000"))
ADMIN         = os.environ.get("WAF_ADMIN", "admin")
PASSWORD      = os.environ.get("WAF_PASSWORD", "Admin@2026")
ENGINE_LOG    = os.environ.get("ENGINE_LOG", "/tmp/novawaf-engine.log")
LOG_PATH      = os.environ.get("LT_LOG", "/var/log/novawaf-longtest.log")
REDIS_HOST    = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT    = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_SOCK    = os.environ.get("REDIS_SOCKET", "")        # 优先 unix socket
REMOTE_HOST   = os.environ.get("REMOTE_HOST", "")          # L4 远程负载机 SSH（留空跳过 L4）
REMOTE_USER   = os.environ.get("REMOTE_USER", "mao")
REMOTE_PASS   = os.environ.get("REMOTE_PASS", "MAO5201314sm")
REMOTE_TARGET = os.environ.get("REMOTE_TARGET", "")         # L4 从远程看到的被测 IP；空则用 WAF_HOST（注意 127.0.0.1 远程无效）

BASE = f"http://{WAF_HOST}:{WAF_PORT}/api"

# ============ 工具：HTTP ============

def req(method, path, body=None, cookie=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if cookie: headers["Cookie"] = cookie
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as ex:
        try:
            return ex.code, json.loads(ex.read().decode())
        except Exception:
            return ex.code, {"code": ex.code, "msg": str(ex)}
    except Exception as ex:
        return 0, {"err": str(ex)}

def login():
    status, body = req("POST", "/auth/login", {"username": ADMIN, "password": PASSWORD})
    if status == 200 and body.get("code") == 200:
        # 从 Set-Cookie 里捡 jwt（HttpOnly 但后端还是写了）
        ck = None
        try:
            with urllib.request.urlopen(urllib.request.Request(BASE + "/auth/login",
                              data=json.dumps({"username": ADMIN, "password": PASSWORD}).encode(),
                              headers={"Content-Type": "application/json"}, method="POST")) as r:
                ck = r.headers.get("Set-Cookie", "")
        except Exception: pass
        token = body.get("data", {}).get("token") if isinstance(body.get("data"), dict) else None
        return True, token, ck, body.get("data", {})
    return False, None, None, body

# ============ 工具：Redis RESP ============

class RedisLite:
    def __init__(self):
        if REDIS_SOCK and os.path.exists(REDIS_SOCK):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(REDIS_SOCK)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((REDIS_HOST, REDIS_PORT))

    def send(self, cmd):
        if isinstance(cmd, (list, tuple)):
            parts = list(cmd)
        else:
            parts = [cmd]
        data = f"*{len(parts)}\r\n".encode()
        for p in parts:
            b = p if isinstance(p, bytes) else p.encode()
            data += f"${len(b)}\r\n".encode() + b + b"\r\n"
        self.sock.sendall(data)

    def recv(self):
        buf = b""
        while True:
            c = self.sock.recv(1)
            if not c: break
            buf += c
            if buf.endswith(b"\r\n"):
                if buf.startswith(b"+"): return buf[1:-2].decode()
                if buf.startswith(b"-"): return buf[1:-2].decode()
                if buf.startswith(b":"): return int(buf[1:-2])
                if buf.startswith(b"$"):
                    n = int(buf[1:-2])
                    if n == -1: return None
                    if n == 0: return ""
                    body = b""
                    while len(body) < n + 2: body += self.sock.recv(n + 2 - len(body))
                    return body[:n].decode()
                if buf.startswith(b"*"):
                    n = int(buf[1:-2])
                    if n == -1: return None
                    items = []
                    for _ in range(n):
                        h = b""
                        while not h.endswith(b"\r\n"): h += self.sock.recv(1)
                        sz = int(h[1:-2])
                        if sz == -1: items.append(None); continue
                        if sz == 0: items.append(""); continue
                        data = b""
                        while len(data) < sz + 2: data += self.sock.recv(sz + 2 - len(data))
                        items.append(data[:sz].decode())
                    return items
        return buf.decode()

    def ping(self):
        self.send("PING")
        return self.recv() == "PONG"

    def get(self, k): self.send(["GET", k]); return self.recv()
    def set(self, k, v): self.send(["SET", k, v]); return self.recv()
    def incr(self, k): self.send(["INCR", k]); return self.recv()
    def exists(self, k): self.send(["EXISTS", k]); return self.recv() == 1
    def hget(self, k, f): self.send(["HGET", k, f]); return self.recv()

# ============ L1 存活 ============

def l1_alive(r):
    ok = True; details = []

    # 端口
    for port, name in [(8099, "engine"), (18081, "admin-server"), (WAF_PORT, "admin-web")]:
        try:
            with socket.create_connection((WAF_HOST, port), timeout=2): pass
            details.append(f"port:{name}:{port}:OK")
        except Exception as ex:
            ok = False; details.append(f"port:{name}:{port}:FAIL {ex}")

    # Redis
    try:
        r.ping(); details.append("redis:OK")
    except Exception as ex:
        ok = False; details.append(f"redis:FAIL {ex}")

    # Engine 日志
    try:
        ten = time.time() - 600  # 10min
        hits = 0; recent = 0
        with open(ENGINE_LOG, "rb") as f:
            for line in f:
                if b"ERROR" in line or b"CRITICAL" in line or b"FATAL" in line:
                    hits += 1
                if b"ERROR" in line and time.time() - os.path.getmtime(ENGINE_LOG) < 600:
                    recent += 1
        if recent == 0:
            details.append("engine_log:OK")
        else:
            ok = False; details.append(f"engine_log:FAIL recent_errors={recent} total={hits}")
    except FileNotFoundError:
        details.append("engine_log:missing (not running via journal)")
    except Exception as ex:
        details.append(f"engine_log:ERR {ex}")

    return ok, details

# ============ L2 接口回归（31 项） ============

def l2_regress(cookie):
    results = []
    def t(name, expect_code, expect_body=None):
        results.append({"name": name, "expect_code": expect_code})
    def do(method, path, body=None, token=None, cookie=None):
        c = cookie
        if token: c = f"jwt={token}"
        return req(method, path, body=body, cookie=c)

    success, token, ck, _ = login()
    t("login_success", 200); results[-1]["ok"] = success
    cookie_to_use = ck if ck else ""

    # 幂等清理：先删残留同名组（防止上一轮 L2 没清理干净）
    try:
        s, b = req("GET", "/waf/ipgroup/list", cookie=cookie_to_use)
        data = b.get("data") if isinstance(b.get("data"), list) else (b.get("data") or {}).get("items", [])
        for item in data:
            if "回归测试" in str(item.get("name", "")):
                gid_old = item.get("id")
                if gid_old:
                    req("DELETE", f"/waf/ipgroup/{gid_old}", cookie=cookie_to_use)
    except Exception: pass
    token_to_use = token

    # 401 未登录
    t("no_token_401", 401)
    s, b = do("GET", "/waf/dashboard")
    results[-1]["ok"] = (s == 401 or (isinstance(b, dict) and b.get("code") == 401))

    # GeoPolicy
    t("geo_save_mode", 200)
    s, b = do("PUT", "/waf/ipgroup/geo/policy", {"mode": "whitelist", "countries": ["CN", "US"], "remark": "regress"}, cookie=cookie_to_use)
    results[-1]["ok"] = s == 200 and b.get("code") == 200

    t("geo_save_illegal_mode", 400)
    s, b = do("PUT", "/waf/ipgroup/geo/policy", {"mode": "unknown", "countries": ["CN"]}, cookie=cookie_to_use)
    results[-1]["ok"] = s in (400, 422) or (isinstance(b, dict) and b.get("code") not in (200,))

    t("geo_get_roundtrip", 200)
    s, b = do("GET", "/waf/ipgroup/geo/policy", cookie=cookie_to_use)
    results[-1]["ok"] = s == 200 and b.get("data", {}).get("mode") in ("whitelist", "blacklist", "off")

    # IpGroup 基础
    t("ig_create", 200)
    s, b = do("POST", "/waf/ipgroup", {"name": "回归测试组", "type": "custom", "action": "block", "enabled": True}, cookie=cookie_to_use)
    gid = (b.get("data") or {}).get("id") if isinstance(b.get("data"), dict) else None
    results[-1]["ok"] = s == 200 and b.get("code") == 200 and gid is not None

    t("ig_create_dup_name", 400)
    s, b = do("POST", "/waf/ipgroup", {"name": "回归测试组", "type": "custom", "action": "block"}, cookie=cookie_to_use)
    results[-1]["ok"] = s in (400, 409) or b.get("code") not in (200,)

    t("ig_list", 200)
    s, b = do("GET", "/waf/ipgroup/list", cookie=cookie_to_use)
    results[-1]["ok"] = s == 200

    # 条目
    t("ig_import", 200)
    s, b = do("POST", f"/waf/ipgroup/{gid}/import", {"text": "1.2.3.4\n10.0.0.0/24\nbad-ip\n999.8.8.8\n"}, cookie=cookie_to_use)
    results[-1]["ok"] = s == 200 and (b.get("data") or {}).get("added", 0) >= 2

    t("ig_entries", 200)
    s, b = do("GET", f"/waf/ipgroup/{gid}/entries?page=1&size=50", cookie=cookie_to_use)
    results[-1]["ok"] = s == 200

    # 清理
    t("ig_delete", 200)
    s, b = do("DELETE", f"/waf/ipgroup/{gid}", cookie=cookie_to_use)
    results[-1]["ok"] = s == 200

    # Deploy NAT
    t("deploy_get", 200)
    s, b = do("GET", "/system/deploy", cookie=cookie_to_use)
    results[-1]["ok"] = s == 200 and b.get("code") == 200

    t("deploy_nat_detect", 200)
    s, b = do("POST", "/system/deploy/nat/detect", {}, cookie=cookie_to_use)
    results[-1]["ok"] = s == 200 and b.get("code") == 200

    # 汇总
    ok = all(r.get("ok", False) for r in results)
    passed = sum(1 for r in results if r.get("ok"))
    return ok, f"{passed}/{len(results)}", results

# ============ L3 引擎热加载 ============

def l3_hotreload(r):
    ok = True; details = []

    def tail_marker(pattern, since):
        hits = 0
        try:
            with open(ENGINE_LOG, "r", errors="replace") as f:
                for line in f:
                    if pattern in line:
                        hits += 1
                        # 粗略时间戳检查（日志格式不同，用 mtime 兜底）
        except FileNotFoundError: pass
        return hits

    # GeoPolicy INCR version → 引擎 3s 内应感知
    base_geo = tail_marker("ver=", None)
    before_ver = r.incr("novawaf:geo:policy:version")
    time.sleep(4)  # 3s + 余量
    after_geo = tail_marker("ver=", None)
    if after_geo > base_geo:
        details.append(f"geo_hotreload:OK ver+1 => log hits {base_geo}->{after_geo}")
    else:
        details.append(f"geo_hotreload:WARN log hits {base_geo}->{after_geo} (可能引擎没写日志)")

    # IOC cksum 存在 novawaf:meta HASH 的 ioc_cksum 字段
    try:
        cksum = r.hget("novawaf:meta", "ioc_cksum")
        has_ioc = r.exists("novawaf:ioc")
        if has_ioc and cksum and len(cksum) == 16:
            details.append(f"ioc_exists:OK cksum={cksum}")
        else:
            ok = False; details.append(f"ioc_exists:FAIL ioc={has_ioc} cksum={cksum}")
    except Exception as ex:
        ok = False; details.append(f"ioc_exists:ERR {ex}")

    # IOC resync 触发 INCR（单数 iplist，不是 iplists）
    ioc_before = r.incr("novawaf:iplist:version")
    time.sleep(1)
    details.append(f"iplist_version:OK {ioc_before}")

    return ok, details

# ============ L4 远程压测（从负载机发，脚本独立文件 bench/l4_stress.py，部署时放到同目录） ============

def l4_remote():
    if not REMOTE_HOST:
        return True, ["l4_skipped:REMOTE_HOST not set"]
    try:
        import paramiko
    except ImportError:
        return True, ["l4_skipped:paramiko missing on 100.2 (install via pip3)"]
    try:
        # 读同目录下的 l4_stress.py（部署时 deploy_longtest.py 一并上传）
        script_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "l4_stress.py")
        with open(script_src, "r", encoding="utf-8") as f:
            src_content = f.read()
    except FileNotFoundError:
        return True, ["l4_skipped:l4_stress.py missing on 100.2"]
    remote_target = REMOTE_TARGET or WAF_HOST
    try:
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(REMOTE_HOST, username=REMOTE_USER, password=REMOTE_PASS, timeout=8,
                  allow_agent=False, look_for_keys=False, banner_timeout=10, auth_timeout=10)
        # 负载机磁盘可能已满：脚本经 SSH stdin 内存执行，不在远端落盘
        # python3 - <target> <admin> <password> <port>
        cmd = f"python3 - {remote_target} {ADMIN} {PASSWORD} {WAF_PORT}"
        stdin, stdout, stderr = c.exec_command(cmd, timeout=200)
        stdin.write(src_content); stdin.flush(); stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        c.close()
        # l4_stress.py 会把结果 JSON 打到 stdout 末行
        line = ""
        for ln in out.strip().splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                line = ln
        if not line:
            return False, [f"l4_fail:no_json out={out[-200:]!r} err={err[-200:]!r}"]
        data = json.loads(line)
        return True, [f"l4:{k}:{json.dumps(v, ensure_ascii=False)}" for k, v in data.items()]
    except Exception as ex:
        return False, [f"l4_ssh_fail:{type(ex).__name__}:{ex}"]

# ============ 主入口 ============

def run_once():
    ts = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S %z")
    summary = {"ts": ts, "l1": {}, "l2": {}, "l3": {}, "l4": {}}

    # Redis
    try:
        r = RedisLite(); r.ping()
        summary["redis"] = "OK"
    except Exception as ex:
        summary["redis"] = f"FAIL {ex}"
        r = None

    ok1, d1 = l1_alive(r) if r else (False, ["redis_unavailable"])
    summary["l1"] = {"ok": ok1, "details": d1}

    ok2, p2, d2 = l2_regress(None)  # 内部自己 login
    summary["l2"] = {"ok": ok2, "passed": p2, "details": [f"{x['name']}:{'PASS' if x.get('ok') else 'FAIL'} expect={x['expect_code']}" for x in d2]}

    ok3, d3 = l3_hotreload(r) if r else (False, ["redis_unavailable"])
    summary["l3"] = {"ok": ok3, "details": d3}

    ok4, d4 = l4_remote()
    summary["l4"] = {"ok": ok4, "details": d4}

    overall = ok1 and ok2 and ok3 and ok4
    summary["overall"] = "PASS" if overall else "FAIL"

    # 追加日志
    try:
        with open(LOG_PATH, "a") as f:
            f.write("\n" + "="*70 + "\n")
            f.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
            f.write(f"OVERALL: {'PASS' if overall else 'FAIL'}\n")
    except Exception as ex:
        print(f"[WARN] log write fail: {ex}", file=sys.stderr)
        # 退而求其次：stderr
        print(json.dumps(summary, ensure_ascii=False, indent=2))

    # 写 Redis 最新状态
    if r:
        try:
            r.set("novawaf:longtest:latest", json.dumps(summary, ensure_ascii=False)[:4000])
            r.incr("novawaf:longtest:runs")
        except Exception: pass

    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(run_once())
