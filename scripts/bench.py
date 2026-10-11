#!/usr/bin/env python3
"""NovaWAF 并发压测客户端
- 口径：并发连接数(同时在途请求数)，统计 RPS / 延迟 / 错误分桶
- keepalive 由服务端决定；本端限制并发避免端口耗尽
- 阶梯加压：每级运行指定秒数，结束后检查服务存活
"""
import asyncio, time, sys, statistics, socket, os

URL_PATH = sys.argv[1] if len(sys.argv) > 1 else "/index.html?q=hello"
HOST = "127.0.0.1"
PORT = 18080
LEVELS = [50, 100, 200, 400]      # 每级并发连接数
DURATION = 8                       # 每级持续秒数

REQ = (f"GET {URL_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").encode()

async def one_request():
    """单次请求，返回 (状态, 延迟秒)。状态: ok / conn_err / http_err / timeout"""
    try:
        t0 = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(HOST, PORT), timeout=3.0)
        writer.write(REQ)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(64), timeout=3.0)
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        dt = time.perf_counter() - t0
        txt = data.decode(errors="ignore")
        if txt.startswith("HTTP/1.1 200") or txt.startswith("HTTP/1.1 403"):
            return ("ok", dt)
        return ("http_err", dt)
    except asyncio.TimeoutError:
        return ("timeout", 0)
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return ("conn_err", 0)

async def worker(sem, results):
    while True:
        async with sem:
            r = await one_request()
            results.append(r)

async def level(c, dur):
    sem = asyncio.Semaphore(c)
    results = []
    tasks = [asyncio.create_task(worker(sem, results)) for _ in range(c)]
    await asyncio.sleep(dur)
    for t in tasks: t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    return results

def summarize(results, c):
    ok = [d for s,d in results if s=="ok"]
    n = len(results)
    errs = {s: sum(1 for s2,_ in results if s2==s) for s in ("conn_err","timeout","http_err")}
    tot = sum(d for d in ok)
    rps = len(ok)/DURATION if ok else 0
    if ok:
        lat = sorted(ok)
        p50 = lat[len(lat)//2]*1000
        p95 = lat[int(len(lat)*0.95)]*1000
        p99 = lat[int(len(lat)*0.99)]*1000
        avg = statistics.mean(ok)*1000
    else:
        avg=p50=p95=p99=0
    print(f"  并发{c:>4} | 请求{n:>7} | RPS {rps:>8.0f} | 延迟ms avg{avg:>6.1f} p50{p50:>6.1f} p95{p95:>6.1f} p99{p99:>6.1f} | 错误 conn{errs['conn_err']} time{errs['timeout']} http{errs['http_err']}")
    return rps

async def main():
    print(f"压测目标: http://{HOST}:{PORT}{URL_PATH}")
    print(f"模型: Connection: close (每请求新建连接), 共{len(LEVELS)}级阶梯, 每级{DURATION}s\n")
    for c in LEVELS:
        res = await level(c, DURATION)
        summarize(res, c)
    # 存活检查
    try:
        r = await asyncio.wait_for(one_request(), timeout=3)
        print(f"\n压后存活检查: {'✅ 服务正常' if r[0]=='ok' else '❌ 异常 ' + r[0]}")
    except Exception as e:
        print(f"\n压后存活检查: ❌ {e}")

if __name__ == "__main__":
    asyncio.run(main())
