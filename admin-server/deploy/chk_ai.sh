#!/bin/bash
echo "=== 引擎启动日志里的 AI/超时配置 ==="
grep -iE "AI review|AI cache|timeout|model|endpoint" /tmp/eng_run.log /tmp/novawaf.log 2>/dev/null | head -10
echo ""
echo "=== redis 里的引擎全局配置 ==="
redis-cli -h 127.0.0.1 get novawaf:config 2>/dev/null | head -c 800; echo
redis-cli -h 127.0.0.1 get novawaf:global 2>/dev/null | head -c 400; echo
echo "=== 测 AI 端点是否可达（若配置了） ==="
timeout 4 curl -s -o /dev/null -w "ai_call=%{http_code} t=%{time_total}\n" --max-time 4 http://127.0.0.1:11434/v1/chat/completions 2>&1 || echo "AI端点不可达/未配置"
