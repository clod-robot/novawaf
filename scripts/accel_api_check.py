#!/usr/bin/env python3
# 硬件加速管理接口端到端校验：登录 -> GET/selfTest -> 开/关热切换 -> 401。
# 在被测服务器本地运行（默认打 127.0.0.1:18081）。结束后恢复为“关闭”安全基线。
import json
import sys
import time
import urllib.request
import urllib.error
import http.cookiejar

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18081"

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
TOKEN = [None]


def call(method, path, body=None, auth=True):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if auth:
        if TOKEN[0]:
            req.add_header("Authorization", "Bearer " + TOKEN[0])
    try:
        with op.open(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


fails = 0


def check(name, cond, extra=""):
    global fails
    print(("PASS " if cond else "FAIL ") + name + (" | " + str(extra) if extra else ""))
    if not cond:
        fails += 1


st, body = call("POST", "/api/auth/login",
                {"username": "admin", "password": "Admin@2026"}, auth=False)
check("login", st == 200 and body.get("code") == 200, st)
data = body.get("data") or {}
TOKEN[0] = data.get("token")
check("has_token", bool(TOKEN[0]), "cookie+token")

# 1) 未鉴权访问应被拦截（使用全新、无 Cookie 的 opener）
try:
    na = urllib.request.build_opener()
    req = urllib.request.Request(BASE + "/api/system/accel")
    try:
        with na.open(req, timeout=10) as r:
            st0, b0 = r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            st0, b0 = e.code, json.loads(e.read().decode())
        except Exception:
            st0, b0 = e.code, {}
except Exception as e:
    st0, b0 = 0, {"err": str(e)}
check("unauth_denied", st0 in (401, 403) or b0.get("code") in (401, 403), st0)

# 2) 读取实时状态
st, body = call("GET", "/api/system/accel")
d = body.get("data") or {}
check("view_ok", st == 200 and body.get("code") == 200, st)
check("engine_reachable", d.get("reachable") is True, d.get("activeBackend"))
check("backends_listed", isinstance(d.get("backends"), list) and len(d.get("backends")) == 7,
      [b.get("name") for b in d.get("backends", [])])
avx2 = next((b for b in d.get("backends", []) if b.get("name") == "AVX2"), {})
check("avx2_healthy", avx2.get("state") == "healthy", avx2.get("state"))
check("default_can_turn_off", d.get("enabled") in (True, False))

# 3) 自检
st, body = call("POST", "/api/system/accel/selftest")
sd = body.get("data") or {}
check("selftest_ok", body.get("code") == 200 and sd.get("ok") is True, sd.get("activeBackend"))

# 4) 开启 -> 引擎 2s 内热加载，状态 ~6s 内反映为 AVX2
st, body = call("PUT", "/api/system/accel",
                {"enabled": True, "preferredBackend": "auto",
                 "batchGateMinN": 8, "batchMaxWaitUs": 2000, "offloadIocRebuild": True})
check("enable_put", body.get("code") == 200, body.get("data"))
active_on = None
for _ in range(8):
    time.sleep(2)
    _, b = call("GET", "/api/system/accel")
    dd = b.get("data") or {}
    if dd.get("activeBackend") == "AVX2" and dd.get("engineEnabled") is True:
        active_on = "AVX2"
        break
check("hot_enable_avx2", active_on == "AVX2", active_on)

# 5) 关闭 -> 回到 Scalar
st, body = call("PUT", "/api/system/accel",
                {"enabled": False, "preferredBackend": "auto",
                 "batchGateMinN": 8, "batchMaxWaitUs": 2000, "offloadIocRebuild": True})
check("disable_put", body.get("code") == 200, body.get("data"))
back_scalar = None
for _ in range(8):
    time.sleep(2)
    _, b = call("GET", "/api/system/accel")
    dd = b.get("data") or {}
    if dd.get("activeBackend") == "Scalar" and dd.get("engineEnabled") is False:
        back_scalar = "Scalar"
        break
check("hot_disable_scalar", back_scalar == "Scalar", back_scalar)

# 6) 非法参数应 400
st, body = call("PUT", "/api/system/accel",
                {"enabled": True, "preferredBackend": "quantum",
                 "batchGateMinN": 8, "batchMaxWaitUs": 2000})
check("bad_backend_400", body.get("code") == 400, body.get("msg"))
st, body = call("PUT", "/api/system/accel",
                {"enabled": True, "preferredBackend": "avx2",
                 "batchGateMinN": 99999, "batchMaxWaitUs": 2000})
check("bad_gate_400", body.get("code") == 400, body.get("msg"))

print("RESULT FAILS=%d" % fails)
sys.exit(1 if fails else 0)
