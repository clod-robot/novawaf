#!/bin/bash
pkill -x novawaf-engine 2>/dev/null; sleep 1
cp /tmp/novawaf-engine.new /tmp/novawaf-engine
chmod +x /tmp/novawaf-engine
cd /home/mao/novawaf
NOVA_REDIS_HOST=127.0.0.1 NOVA_YARA_RULES=/home/mao/novawaf/yara-rules nohup /tmp/novawaf-engine > /tmp/novawaf.log 2>&1 &
sleep 2
echo -n "引擎监听: "; ss -ltnp 2>/dev/null | grep ':8099' | head -1
echo -n "进程: "; pgrep -a novawaf-engine | head -1
echo -n "日志尾部: "; tail -3 /tmp/novawaf.log | tr '\n' '|'; echo
