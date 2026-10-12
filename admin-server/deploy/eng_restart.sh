#!/bin/bash
set -e
pkill -x novawaf-engine 2>/dev/null || true
sleep 1
cd /home/mao/novawaf/engine
NOVA_REDIS_HOST=127.0.0.1 NOVA_YARA_RULES=/home/mao/novawaf/yara-rules stdbuf -oL nohup /tmp/novawaf-engine 8099 4 >/tmp/novawaf.log 2>&1 &
sleep 3
echo "--- listeners ---"
ss -tlnp 2>/dev/null | grep 8099 | head
echo "--- log tail ---"
tail -8 /tmp/novawaf.log
echo "RESTARTED"
