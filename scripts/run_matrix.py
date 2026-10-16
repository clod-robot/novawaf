#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NovaWAF 硬件加速四组对比压测编排器（本机 Windows 运行，驱动两台 Linux 主机）。

四组：
  A = 加速关(Scalar) + CC/DDoS 关(超大阈值)
  B = 加速开(AVX2)   + CC/DDoS 关
  C = 加速关(Scalar) + CC/DDoS 开(评估热路径生效、阈值高于单机速率不封禁)
  D = 加速开(AVX2)   + CC/DDoS 开
每组 N 轮，每轮 DURATION 秒，固定并发，负载来自独立负载机。
结果增量写入本地 results JSON，便于后台执行时观察进度。

用法：python3 run_matrix.py [rounds=3] [duration=60] [out=...matrix_results.json]
"""
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REMOTE_PY = os.path.join(HERE, "accel_remote.py")
REDIS_PY = os.path.join(HERE, "accel_redis.py")
BENCH_PY = os.path.join(HERE, "accel_bench.py")
TMP = os.path.normpath(os.path.join(HERE, "..", "..", ".acceltmp"))

SERVER = "192.168.100.2"   # 被测引擎
LOADER = "192.168.100.4"   # 独立负载机
USER = "mao"
PASS = "MAO5201314sm"
PORT = "8099"
PROCS, THREADS, RATIO = 4, 32, 0.7

GROUPS = [
    # name, ddos_profile, accel_on, expect_backend
    ("A", "off", False, "Scalar"),
    ("B", "off", True, "AVX2"),
    ("C", "on", False, "Scalar"),
    ("D", "on", True, "AVX2"),
]


def host_env(host):
    e = dict(os.environ)
    e.update(NOVA_HOST=host, NOVA_USER=USER, NOVA_PASS=PASS)
    return e


def rexec(host, cmd, timeout=120):
    p = subprocess.run([sys.executable, REMOTE_PY, "exec", cmd, str(timeout)],
                       capture_output=True, text=True, env=host_env(host), timeout=timeout + 20)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def rputin(host, local, remote):
    p = subprocess.run([sys.executable, REMOTE_PY, "putin", local, remote],
                       capture_output=True, text=True, env=host_env(host), timeout=60)
    if p.returncode != 0:
        raise RuntimeError(f"putin {local}->{host}:{remote} failed: {p.stderr or p.stdout}")


def bench_round(host, tag, duration):
    args = ["python3", "-", SERVER, PORT, str(duration), str(PROCS), str(THREADS),
            str(RATIO), tag, "bench.test"]
    p = subprocess.run([sys.executable, REMOTE_PY, "stdin", BENCH_PY, *args],
                       capture_output=True, text=True, env=host_env(host), timeout=duration + 60)
    line = None
    for ln in p.stdout.splitlines():
        if ln.startswith("{"):
            line = ln
    if not line:
        raise RuntimeError(f"bench {tag} no JSON: rc={p.returncode} out={p.stdout[-300:]} err={p.stderr[-300:]}")
    return json.loads(line)


def wait_health():
    rc, out, err = rexec(SERVER,
        "curl -s -o /dev/null -w '%{http_code}' -H 'Host: bench.test' 'http://127.0.0.1:8099/health?z=1'", 30)
    if out != "200":
        raise RuntimeError(f"engine health not 200: {out} {err}")


def set_profile(profile):
    conf = f"/tmp/bench-{profile}.conf"
    cmd = (f"echo {PASS} | sudo -S cp {conf} /etc/systemd/system/novawaf-engine.service.d/override.conf ; "
           f"echo {PASS} | sudo -S systemctl daemon-reload ; "
           f"echo {PASS} | sudo -S systemctl restart novawaf-engine ; sleep 6 ; "
           f"systemctl is-active novawaf-engine")
    rc, out, err = rexec(SERVER, cmd, 90)
    if "active" not in out:
        raise RuntimeError(f"restart profile={profile} failed: {out} {err}")
    wait_health()


def set_accel(on, expect):
    cfg = "/tmp/accel_on.json" if on else "/tmp/accel_off.json"
    rexec(SERVER,
          f"python3 /tmp/accel_redis.py SETFILE novawaf:accel:config {cfg} ; "
          f"python3 /tmp/accel_redis.py INCR novawaf:accel:version", 30)
    # 内存 2s 切换；status 每 ~6s 发布一次，故轮询等待 activeBackend
    ok = False
    last = ""
    for _ in range(10):
        time.sleep(2)
        rc, out, err = rexec(SERVER, "python3 /tmp/accel_redis.py GET novawaf:accel:status", 20)
        last = out
        if f'"activeBackend":"{expect}"' in out.replace(" ", ""):
            ok = True
            break
    if not ok:
        raise RuntimeError(f"accel expect {expect} not confirmed: {last[-400:]}")


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    out_path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(TMP, "matrix_results.json")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    # 1) 确保远端工具与配置就位
    for f in ("accel_off.json", "accel_on.json", "bench-off.conf", "bench-on.conf"):
        rputin(SERVER, os.path.join(TMP, f), f"/tmp/{f}")
    rputin(SERVER, REDIS_PY, "/tmp/accel_redis.py")

    results = {"rounds": rounds, "duration_s": duration, "concurrency": PROCS * THREADS,
               "attack_ratio": RATIO, "server": SERVER, "loader": LOADER, "groups": {}}

    def save():
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    cur_profile = None
    for name, profile, on, expect in GROUPS:
        if profile != cur_profile:
            print(f"== profile switch -> {profile} ==", flush=True)
            set_profile(profile)
            cur_profile = profile
            time.sleep(1)
        print(f"== accel -> {'ON '+expect if on else 'OFF Scalar'} ==", flush=True)
        set_accel(on, expect)
        rows = []
        for r in range(1, rounds + 1):
            tag = f"g{name}r{r}"
            print(f"[{name}] round {r}/{rounds} load {duration}s ...", flush=True)
            t0 = time.time()
            row = bench_round(LOADER, tag, duration)
            row["wall_local_s"] = round(time.time() - t0, 1)
            row["normal_false_403"] = row["codes"].get("403", 0) - row["attack_blocked_403"]
            row["ok"] = (row["attack_miss"] == 0
                         and row["conn_errors"] / max(1, row["total"]) < 0.05)
            rows.append(row)
            results["groups"][name] = {
                "profile": profile, "accel": "AVX2" if on else "Scalar", "rounds": rows}
            save()
            print(f"    rps={row['rps']} miss={row['attack_miss']} "
                  f"p99={row['p99_ms']}ms err={row['conn_errors']} ok={row['ok']}", flush=True)
            time.sleep(2)

    # 汇总：每组 RPS 中位数
    summary = {}
    for name, _, _, _ in GROUPS:
        rps = [r["rps"] for r in results["groups"][name]["rounds"]]
        summary[name] = {"rps_rounds": rps, "rps_median": round(statistics.median(rps), 1),
                         "attack_miss": sum(r["attack_miss"] for r in results["groups"][name]["rounds"])}
    summary["B_over_A_pct"] = round(100 * (summary["B"]["rps_median"] / summary["A"]["rps_median"] - 1), 1)
    summary["D_over_C_pct"] = round(100 * (summary["D"]["rps_median"] / summary["C"]["rps_median"] - 1), 1)
    results["summary"] = summary
    save()
    print("SUMMARY " + json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
