#!/bin/bash
pkill -x novawaf-engine 2>/dev/null; sleep 2
cd /home/mao/novawaf
: > /tmp/eng_run.log
NOVA_REDIS_HOST=127.0.0.1 NOVA_YARA_RULES=/home/mao/novawaf/yara-rules nohup /tmp/novawaf-engine 8099 4 > /tmp/eng_run.log 2>&1 &
sleep 3
echo "alive=$(pgrep -x novawaf-engine >/dev/null && echo YES || echo NO)"
echo "ss8099:"; ss -ltn 2>/dev/null | grep ':8099'
echo "curl_waf:"; curl -s -o /dev/null -w "%{http_code}\n" --max-time 3 http://127.0.0.1:8099/ -H "Host: nac"
echo "--- log head ---"; head -8 /tmp/eng_run.log
