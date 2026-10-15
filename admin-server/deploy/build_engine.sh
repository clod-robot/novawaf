#!/bin/bash
cd /home/mao/novawaf/engine
echo "[1/2] 编译引擎..."
g++ -std=c++20 -O2 -I include src/main.cpp -o /tmp/novawaf-engine -pthread -lyara 2> /tmp/build_err.txt
RC=$?
if [ $RC -ne 0 ]; then echo "BUILD_FAIL rc=$RC"; tail -30 /tmp/build_err.txt; exit 1; fi
ls -la /tmp/novawaf-engine | awk '{print "  built:", $5, $6, $7, $8}'
echo "BUILD_OK"

echo "[2/2] 重启引擎..."
pkill -x novawaf-engine 2>/dev/null; sleep 1
cd /home/mao/novawaf/engine
NOVA_REDIS_HOST=127.0.0.1 NOVA_YARA_RULES=/home/mao/novawaf/yara-rules stdbuf -oL nohup /tmp/novawaf-engine 8099 4 >/tmp/novawaf.log 2>&1 &
sleep 3
echo "  监听 8099:"; (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep 8099 | head -4
echo "  启动日志(名单加载):"; grep -i 'IpList\|listening\|reactor' /tmp/novawaf.log | head -6
echo "ENGINE_DONE"