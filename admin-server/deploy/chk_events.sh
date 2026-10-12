#!/bin/bash
echo "=== 触发一次拦截 ==="
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: nac" http://127.0.0.1:8099/api/auth/system/info
sleep 1
echo "=== 管理端 events（最近） ==="
curl -s --max-time 5 "http://127.0.0.1:18081/api/waf/events?limit=8" 2>&1 | head -c 1500; echo
echo "=== 管理端 logs（最近） ==="
curl -s --max-time 5 "http://127.0.0.1:18081/api/waf/logs?limit=8" 2>&1 | head -c 1500; echo
