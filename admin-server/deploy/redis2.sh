#!/bin/bash
echo "=== redis 连通性 ==="
redis-cli -h 127.0.0.1 ping 2>&1
echo "=== 全量键（不限 pattern） ==="
redis-cli -h 127.0.0.1 --scan --pattern '*' 2>/dev/null | head -30
echo "=== 可能需要密码？试常见 ==="
redis-cli -h 127.0.0.1 -a '' ping 2>&1 | head -1
echo "=== 看引擎 emitEvt 写到哪个流：grep 运行进程环境 ==="
tr '\0' '\n' < /proc/$(pgrep -x novawaf-engine | head -1)/environ 2>/dev/null | grep -i redis
