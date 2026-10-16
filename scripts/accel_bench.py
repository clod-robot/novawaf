#!/usr/bin/env python3
"""NovaWAF 硬件加速数据面压测（在负载机 192.168.100.4 上运行，打 192.168.100.2:8099）。

特性：
  - 多进程 + 多线程，长连接 HTTP/1.1 keep-alive，尽量避免压测端成为瓶颈；
  - 混合 攻击(默认70%，应被 WAF 拦截 403) / 正常(应透传 200)；
  - 统计 RPS、p50/p95/p99/p999/max、状态码分布、连接错误、攻击漏报数；
  - warmup 3s 不计入统计。

用法:
  python3 accel_bench.py <host> <port> <duration> <procs> <threads_per_proc> <attack_ratio> <tag> [host_header]
例:
  python3 accel_bench.py 192.168.100.2 8099 60 4 32 0.7 A_scalar_ddosoff bench.test
输出: stdout JSON + /tmp/accel_bench_<tag>.json
"""
import json
import multiprocessing as mp
import random
import socket
import sys
import threading
import time

# 攻击负载：均为引擎规则集可稳定拦截的模式（URL 编码后在查询串中）
ATTACKS = [
    "/?id=1%27%20or%20%271%27=%271",
    "/?id=1%20union%20select%20user%2Cpass%20from%20users--",
    "/?q=%3Cscript%3Ealert%281%29%3C/script%3E",
    "/?x=%3Cimg%20src=x%20onerror=alert%281%29%3E",
    "/?f=%3Bcat%20%2Fetc%2Fpasswd",
    "/?p=..%2F..%2F..%2Fetc%2Fpasswd",
    "/?u=1%27%20and%20sleep%285%29--",
    "/?a=sqlmap%20injection%20union%20select",
    "/?b=%3C%21ENTITY%20x%20SYSTEM%20%22file%3A%2Fetc%2Fpasswd%22%3E",
    "/?c=nikto%20scanner%20union%20select",
]
NORMALS = [
    "/", "/index.html", "/health", "/api/health", "/about",
    "/static/app.js", "/static/style.css", "/img/logo.png",
    "/products", "/docs/intro", "/api/v1/time", "/favicon.ico",
]


class Buf:
    """带前向缓冲的最小 socket 读取器"""
    __slots__ = ("s", "b")

    def __init__(self, s):
        self.s = s
        self.b = b""

    def _fill(self, need=1):
        d = self.s.recv(65536)
        if not d:
            raise EOFError("closed")
        self.b += d

    def readline(self):
        while b"\r\n" not in self.b:
            self._fill()
        line, self.b = self.b.split(b"\r\n", 1)
        return line

    def read(self, n):
        while len(self.b) < n:
            self._fill()
        out, self.b = self.b[:n], self.b[n:]
        return out


def one_request(buf, host_header):
    """发起一次请求并读取完整响应，返回状态码"""
    is_atk = random.random() < float(__RATIO__)
    if __BODY_KB__ > 0:
        # 大体积 POST：攻击载体放在请求体前部（确保落入可扫描前缀），其余为良性大报文
        n = __BODY_KB__ * 1024
        # 带随机查询串打散 per-URL 计数，避免 CC/行为防护把单一负载 IP 判成高频同 URL
        path = random.choice(NORMALS) + "?n=" + str(random.randint(1, 10 ** 6))
        if is_atk:
            payload = b"&z=1' union select password from users -- "
            pre = 200
            body = FILLER[:pre] + payload + FILLER[: max(0, n - pre - len(payload))]
        else:
            body = FILLER[:n]
        body = body[:n].ljust(n, b"0")
        req = (f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: accel-bench\r\n"
               "Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
               "Connection: keep-alive\r\n\r\n").encode() + body
    else:
        if is_atk:
            path = random.choice(ATTACKS)
        else:
            # 正常路径带随机参数，避免命中同 URL 突刺 CC
            path = random.choice(NORMALS) + ("?n=" + str(random.randint(1, 10 ** 6)))
        if __QSIZE__ > 0:
            # 在查询串追加纯数字填充，增大单请求被规则引擎扫描的字节数（匹配占比↑）
            sep = "&" if "?" in path else "?"
            path = path + sep + "pad=" + NUMPAD[:__QSIZE__]
        req = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: accel-bench\r\n"
               "Accept: */*\r\nConnection: keep-alive\r\n\r\n").encode()
    buf.s.sendall(req)

    status = buf.readline()
    parts = status.split(b" ", 2)
    code = int(parts[1]) if len(parts) >= 2 else 0
    clen = -1
    close = False
    while True:
        line = buf.readline()
        if not line:
            break
        low = line.lower()
        if low.startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1].strip())
        elif low.startswith(b"connection:") and b"close" in low:
            close = True
        elif low.startswith(b"transfer-encoding:") and b"chunked" in low:
            clen = -2
    if clen == -2:  # chunked：读到 0 长度块（WAF 基本不用，保险起见读到 close 标记）
        while True:
            size_line = buf.readline()
            size = int(size_line.split(b";", 1)[0], 16)
            if size == 0:
                buf.readline()
                break
            buf.read(size); buf.read(2)
    elif clen >= 0:
        if clen:
            buf.read(clen)
    if close:
        raise EOFError("server-close")
    return code, is_atk


# 进程内全局（由 worker_proc 注入）
__RATIO__ = 0.7
__BODY_KB__ = 0
__QSIZE__ = 0
FILLER = b""
NUMPAD = ""
# 仅数字 + 极少量字母(k)/分隔符，保证大体积正常报文不会偶然拼出任何攻击关键字
_FILL_SEED = b"k=1234567890&k2=9876543210&"


def worker_thread(target, port, host_header, stop_at, counters, latencies, tlock):
    rng = random.Random()  # noqa
    random.seed(rng.randint(0, 2 ** 31))
    while time.time() < stop_at:
        buf = None
        try:
            s = socket.create_connection((target, port), timeout=5)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5)
            buf = Buf(s)
            # 每条连接上复用多个请求，直到连接关闭或计时结束
            while time.time() < stop_at:
                t0 = time.perf_counter()
                code, is_atk = one_request(buf, host_header)
                lat = (time.perf_counter() - t0) * 1000.0
                with tlock:
                    counters["n"] += 1
                    counters[code] = counters.get(code, 0) + 1
                    if is_atk:
                        counters["atk"] += 1
                        counters["atk_blk"] += 1 if code == 403 else 0
                    else:
                        counters["norm"] += 1
                        counters["norm_ok"] += 1 if code == 200 else 0
                    latencies.append(lat)
        except Exception:
            with tlock:
                counters["err"] += 1
            time.sleep(0.01)
        finally:
            try:
                if buf is not None:
                    buf.s.close()
            except Exception:
                pass


def worker_proc(q, target, port, duration, warmup, threads, ratio, host_header, seed,
                body_kb=0, qsize=0):
    global __RATIO__, __BODY_KB__, __QSIZE__, FILLER, NUMPAD
    __RATIO__ = ratio
    __BODY_KB__ = body_kb
    __QSIZE__ = qsize
    if body_kb > 0:
        want = (body_kb + 64) * 1024
        FILLER = (_FILL_SEED * ((want // len(_FILL_SEED)) + 1))[:want]
    if qsize > 0:
        NUMPAD = ("0123456789" * ((qsize // 10) + 1))[:qsize]
    random.seed(seed)
    counters = {"n": 0, "atk": 0, "atk_blk": 0, "norm": 0, "norm_ok": 0, "err": 0}
    latencies = []
    tlock = threading.Lock()
    # warmup：先跑一段并丢弃
    stop_warm = time.time() + warmup
    ts = []
    for _ in range(threads):
        t = threading.Thread(target=worker_thread,
                             args=(target, port, host_header, stop_warm, counters, latencies, tlock), daemon=True)
        t.start(); ts.append(t)
    for t in ts: t.join()
    # 清零，正式测量
    for k in list(counters.keys()):
        counters[k] = 0
    latencies.clear()
    measure_start = time.time()
    stop_at = measure_start + duration
    ts = []
    for i in range(threads):
        t = threading.Thread(target=worker_thread,
                             args=(target, port, host_header, stop_at, counters, latencies, tlock), daemon=True)
        t.start(); ts.append(t)
    for t in ts: t.join()
    q.put((counters, latencies))


def pct(sorted_lat, p):
    if not sorted_lat:
        return 0.0
    i = min(len(sorted_lat) - 1, int(len(sorted_lat) * p))
    return round(sorted_lat[i], 2)


def main():
    target = sys.argv[1]
    port = int(sys.argv[2])
    duration = float(sys.argv[3])
    procs = int(sys.argv[4])
    threads = int(sys.argv[5])
    ratio = float(sys.argv[6])
    tag = sys.argv[7]
    host_header = sys.argv[8] if len(sys.argv) > 8 else "bench.test"
    body_kb = int(sys.argv[9]) if len(sys.argv) > 9 else 0
    qsize = int(sys.argv[10]) if len(sys.argv) > 10 else 0
    warmup = 3.0

    q = mp.Queue()
    ps = []
    t_wall = time.time()
    for i in range(procs):
        p = mp.Process(target=worker_proc,
                       args=(q, target, port, duration, warmup, threads, ratio, host_header,
                             random.randint(0, 2 ** 31) + i, body_kb, qsize))
        p.start(); ps.append(p)
    agg = {"n": 0, "atk": 0, "atk_blk": 0, "norm": 0, "norm_ok": 0, "err": 0}
    codes = {}
    all_lat = []
    for _ in ps:
        counters, lat = q.get()
        for k in ("n", "atk", "atk_blk", "norm", "norm_ok", "err"):
            agg[k] += counters.get(k, 0)
        for k, v in counters.items():
            if isinstance(k, int):
                codes[str(k)] = codes.get(str(k), 0) + v
        all_lat.extend(lat)
    for p in ps: p.join()
    all_lat.sort()
    n = agg["n"]
    res = {
        "tag": tag, "target": f"{target}:{port}", "procs": procs, "threads": threads,
        "concurrency": procs * threads, "attackRatio": ratio, "bodyKb": body_kb, "queryPad": qsize,
        "duration_s": duration, "measured_wall_s": round(duration, 2),
        "total": n, "rps": round(n / duration, 1),
        "attack_total": agg["atk"], "attack_blocked_403": agg["atk_blk"],
        "attack_miss": agg["atk"] - agg["atk_blk"],
        "normal_total": agg["norm"], "normal_200": agg["norm_ok"],
        "conn_errors": agg["err"], "codes": codes,
        "p50_ms": pct(all_lat, 0.50), "p95_ms": pct(all_lat, 0.95),
        "p99_ms": pct(all_lat, 0.99), "p999_ms": pct(all_lat, 0.999),
        "max_ms": round(all_lat[-1], 2) if all_lat else 0,
    }
    out = json.dumps(res, ensure_ascii=False)
    print(out)
    try:
        with open(f"/tmp/accel_bench_{tag}.json", "w") as f:
            f.write(out)
    except Exception:
        pass
    # 攻击有任何漏报 / 连接大量错误 时非零退出，供编排脚本判定
    bad = (res["attack_miss"] != 0) or (res["conn_errors"] > n * 0.05)
    sys.exit(2 if bad else 0)


if __name__ == "__main__":
    main()
