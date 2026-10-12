#!/bin/bash
pkill -x novawaf-engine 2>/dev/null; sleep 1
cd /home/mao/novawaf
NOVA_REDIS_HOST=127.0.0.1 NOVA_YARA_RULES=/home/mao/novawaf/yara-rules /tmp/novawaf-engine > /tmp/eng_fg.log 2>&1 &
EP=$!
sleep 2
echo "pid=$EP alive=$(kill -0 $EP 2>/dev/null && echo yes || echo no)"
head -20 /tmp/eng_fg.log
