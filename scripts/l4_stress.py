"""L4 远程压测脚本（在负载机 192.168.100.4 上执行）。
由 long_test_full.py 经 SSH stdin 内存投递（python3 - <target> <admin> <password> <port>），
不落盘——负载机磁盘可能已满。结果 JSON 打到 stdout 末行由调用方解析；
若磁盘可写，另存 /tmp/l4_result.json（仅为兜底）。
"""
import json, sys, time, urllib.request, threading, queue, os

HOST = sys.argv[1]
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "Admin@2026"
PORT = sys.argv[4] if len(sys.argv) > 4 else "9000"
BASE = f"http://{HOST}:{PORT}/api"


def http(method, path, body=None, headers=None, timeout=5):
    d = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"}
    if headers: hdrs.update(headers)
    r = urllib.request.Request(BASE + path, data=d, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode()), resp.headers.get("Set-Cookie", "")
    except Exception as ex:
        return 0, str(ex), ""


def run_constant_rps(path, body, duration=30, rps=50, headers=None, method="POST"):
    """恒定 RPS 压测，返回统计 dict"""
    latencies = queue.Queue()
    errors = queue.Queue()
    stop = threading.Event()
    success = threading.Event()

    def worker():
        while not stop.is_set():
            t0 = time.time()
            try:
                d = json.dumps(body).encode() if body is not None else None
                hdrs = {"Content-Type": "application/json"}
                if headers: hdrs.update(headers)
                r = urllib.request.Request(BASE + path, data=d, method=method, headers=hdrs)
                with urllib.request.urlopen(r, timeout=5) as resp:
                    resp.read()
                latencies.put(time.time() - t0)
            except Exception as ex:
                errors.put(1)
                latencies.put(time.time() - t0)

    # 启动 worker 线程（rps 个并发）
    threads = []
    for _ in range(min(rps, 20)):
        t = threading.Thread(target=worker, daemon=True); t.start(); threads.append(t)

    # 发压：主线程恒定 RPS
    success_count = 0
    fail_count = 0
    start = time.time()
    last = start
    interval = 1.0 / rps if rps > 0 else 0.01

    while time.time() - start < duration:
        t0 = time.time()
        try:
            d = json.dumps(body).encode() if body is not None else None
            hdrs = {"Content-Type": "application/json"}
            if headers: hdrs.update(headers)
            r = urllib.request.Request(BASE + path, data=d, method=method, headers=hdrs)
            with urllib.request.urlopen(r, timeout=5) as resp:
                resp.read()
            success_count += 1
            latencies.put(time.time() - t0)
        except Exception:
            fail_count += 1
            latencies.put(time.time() - t0)

        # 控制 RPS
        elapsed = time.time() - last
        if elapsed < interval: time.sleep(interval - elapsed)
        last = time.time()

    stop.set()
    # 等线程结束
    for t in threads: t.join(timeout=2)

    # 取所有延迟
    all_lat = []
    while not latencies.empty():
        try: all_lat.append(latencies.get_nowait())
        except: break

    if not all_lat:
        return {"p50": 0, "p95": 0, "p99": 0, "max": 0, "rps": 0, "success": success_count, "fail": fail_count}

    all_lat.sort()
    n = len(all_lat)
    return {
        "p50": round(all_lat[int(n * 0.5)] * 1000, 1),
        "p95": round(all_lat[int(n * 0.95)] * 1000, 1),
        "p99": round(all_lat[int(n * 0.99)] * 1000, 1),
        "max": round(all_lat[-1] * 1000, 1),
        "rps": round(success_count / duration, 1),
        "success": success_count,
        "fail": fail_count,
    }


def main():
    result = {}

    # 1. 登录拿 cookie
    try:
        r = urllib.request.Request(
            BASE + "/auth/login",
            data=json.dumps({"username": ADMIN, "password": PASSWORD}).encode(),
            method="POST", headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(r, timeout=10)
        set_cookie = resp.headers.get("Set-Cookie", "")
        login_json = json.loads(resp.read())
        token = login_json.get("data", {}).get("token") or login_json.get("token")
        cookie = set_cookie.split(";")[0] if set_cookie else (f"jwt={token}" if token else "")
        headers = {"Cookie": cookie}
        result["login_ok"] = True
    except Exception as ex:
        result["login_ok"] = False
        result["login_err"] = str(ex)[:200]
        # 即使 login fail 也继续测（可能接口不需要 cookie）
        headers = {}

    # 2. 三个接口 30s 压测
    result["login_bench"] = run_constant_rps("/auth/login", {"username": ADMIN, "password": PASSWORD},
                                              duration=15, rps=30)
    result["ipgroup_list"] = run_constant_rps("/waf/ipgroup/list", None, duration=15, rps=30,
                                              headers=headers, method="GET")
    result["blacklist"] = run_constant_rps("/waf/iplist?type=black", None, duration=15, rps=30,
                                           headers=headers, method="GET")
    result["target"] = HOST
    result["ts"] = int(time.time())

    # 写结果到文件（避免 paramiko channel 读超时）
    try:
        with open("/tmp/l4_result.json", "w") as f:
            json.dump(result, f, ensure_ascii=False)
    except Exception as ex:
        print(f"write fail: {ex}", file=sys.stderr)

    # 也 print 一下（短输出）
    summary = {}
    for k, v in result.items():
        if isinstance(v, dict):
            summary[k] = {kk: vv for kk, vv in v.items() if kk in ("p50", "p95", "p99", "rps", "success", "fail")}
        else:
            summary[k] = v
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
