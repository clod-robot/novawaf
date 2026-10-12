#!/bin/bash
echo "=== 监听中的 TCP 端口(含进程) ==="
ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4, $6}' | head -40
echo
echo "=== java 进程 ==="
ps -ef | grep '[j]ava'
echo
echo "=== novawaf:apps 当前内容 ==="
/usr/local/redis/bin/redis-cli -h 127.0.0.1 GET novawaf:apps
echo "=== novawaf:apps:version ==="
/usr/local/redis/bin/redis-cli -h 127.0.0.1 GET novawaf:apps:version
