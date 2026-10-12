#!/usr/bin/env python3
"""模拟引擎侧 clamd INSTREAM 扫描：PING + EICAR 检测。"""
import socket, struct, sys
HOST, PORT = "127.0.0.1", 3310
def cmd(s, c):
    s.sendall((c + "\n").encode()); return s.recv(4096).decode(errors="replace").strip()
def scan(data: bytes) -> str:
    s = socket.create_connection((HOST, PORT), timeout=30)
    s.sendall(b"zINSTREAM\0")
    # 分块发送（每块 <= 64KB，前缀 4 字节大端长度；以 0 长度结束）
    view = memoryview(data)
    i = 0
    while i < len(view):
        chunk = view[i:i+65536].tobytes()
        s.sendall(struct.pack(">I", len(chunk)) + chunk)
        i += len(chunk)
    s.sendall(struct.pack(">I", 0))
    s.shutdown(socket.SHUT_WR)
    out = b""
    while True:
        r = s.recv(4096)
        if not r: break
        out += r
    s.close()
    return out.decode(errors="replace").strip()

s = socket.create_connection((HOST, PORT), timeout=10)
s.settimeout(30)
# 轮询 PING 直到 clamd 加载完签名库就绪（首次加载 main.cvd 可能需数十秒）
import time
pong = ""
for _ in range(60):
    try:
        pong = cmd(s, "PING")
        if pong: break
    except Exception:
        time.sleep(3)
        try: s.close()
        except Exception: pass
        s = socket.create_connection((HOST, PORT), timeout=10); s.settimeout(30)
print("PING   ->", pong or "(no response)")
s2 = socket.create_connection((HOST, PORT), timeout=10); s2.settimeout(30)
print("VERSION->", cmd(s2, "VERSION")); s2.close()
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
CLEAN = b'hello world this is clean normal text content'
print("EICAR  ->", scan(EICAR))
print("CLEAN  ->", scan(CLEAN))
ok = ("FOUND" in scan(EICAR)) and ("OK" in scan(CLEAN))
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
