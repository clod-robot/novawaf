"""L4 阶梯并发压测（建议1改进版）。
替代 l4_stress.py 的主线程串行模型——N 个 worker 线程各自循环发请求并全部计入统计，
度量真实服务端吞吐。stdlib only，经 SSH stdin 投递执行（python3 - <host> [port] [admin] [pass]），
负载机不落盘。每档输出一行 JSON，最后输出 SUMMARY。
"""
import json, sys, time, urllib.request, threading, queue

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.100.2"
PORT = sys.argv[2] if len(sys.argv) > 2 else "9000"
ADMIN = sys.argv[3] if len(sys.argv) > 3 else "admin"
PASSWORD = sys.argv[4] if len(sys.argv) > 4 else "Admin@2026"
BASE = f"http://{HOST}:{PORT}/api"
REQ_TIMEOUT = 15


def one_req(path, method, body, cookie):
    d = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"}
    if cookie:
        hdrs["Cookie"] = cookie
    r = urllib.request.Request(BASE + path, data=d, method=method, headers=hdrs)
    t0 = time.time()
    try:
        with urllib.request.urlopen(r, timeout=REQ_TIMEOUT) as resp:
            resp.read()
            return time.time() - t0, resp.status < 400
    except Exception:
        return time.time() - t0, False


def do_login():
    lat, ok = one_req("/auth/login", "POST", {"username": ADMIN, "password": PASSWORD}, None)
    if not ok:
        return None
    r = urllib.request.Request(BASE + "/auth/login",
                               data=json.dumps({"username": ADMIN, "password": PASSWORD}).encode(),
                               method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=REQ_TIMEOUT) as resp:
            set_cookie = resp.headers.get("Set-Cookie", "")
            body = json.loads(resp.read().decode())
        token = body.get("data", {}).get("token") or body.get("token")
        return set_cookie.split(";")[0] if set_cookie else (f"jwt={token}" if token else "")
    except Exception:
        return None


def pct(sorted_lats, p):
    if not sorted_lats:
        return 0
    return round(sorted_lats[min(len(sorted_lats) - 1, int(len(sorted_lats) * p))] * 1000, 1)


def step(name, path, method, body, cookie, conc, dur):
    q = queue.Queue()
    stop = threading.Event()

    def worker():
        while not stop.is_set():
            lat, ok = one_req(path, method, body, cookie)
            q.put((lat, ok))

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(conc)]
    for t in threads:
        t.start()
    t0 = time.time()
    time.sleep(dur)
    stop.set()
    for t in threads:
        t.join(timeout=REQ_TIMEOUT + 2)
    real_dur = time.time() - t0

    lats, errs = [], 0
    while True:
        try:
            lat, ok = q.get_nowait()
        except queue.Empty:
            break
        lats.append(lat)
        if not ok:
            errs += 1
    lats.sort()
    total = len(lats)
    row = {
        "name": name, "conc": conc, "dur": round(real_dur, 1), "total": total,
        "err": errs, "err_pct": round(errs * 100.0 / total, 2) if total else 100.0,
        "rps": round(total / real_dur, 1),
        "p50": pct(lats, 0.50), "p95": pct(lats, 0.95), "p99": pct(lats, 0.99),
        "max": round(lats[-1] * 1000, 1) if lats else 0,
        "ts": int(t0),
    }
    print("STEP " + json.dumps(row, ensure_ascii=False), flush=True)
    return row


def main():
    cookie = do_login()
    print("LOGIN_COOKIE " + ("ok" if cookie is not None else "fail"), flush=True)
    creds = {"username": ADMIN, "password": PASSWORD}
    plan = [
        ("ipgroup_list", "/waf/ipgroup/list", "GET", None, cookie, [1, 5, 10, 20, 50, 100], 15),
        ("blacklist", "/waf/iplist?type=black", "GET", None, cookie, [1, 5, 10, 20, 50], 15),
        ("login_bench", "/auth/login", "POST", creds, None, [1, 5, 10], 10),
    ]
    rows = []
    for name, path, method, body, ck, concs, dur in plan:
        for conc in concs:
            rows.append(step(name, path, method, body, ck, conc, dur))
            time.sleep(3)  # 档间回落
    print("SUMMARY " + json.dumps({"target": HOST, "steps": len(rows),
                                   "ts": int(time.time())}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
