#!/bin/bash
echo "=== 1. 复现：请求 system/info，看返回码与体 ==="
curl -sk -i --max-time 6 https://127.0.0.1/api/auth/system/info -H "Host: 192.168.100.2" 2>&1 | head -20
echo ""
echo "=== 2. 经 WAF(8099) 直打，看是否 403 ==="
curl -s -o /dev/null -w "code=%{http_code} t=%{time_total}\n" --max-time 6 -H "Host: nac" http://127.0.0.1:8099/api/auth/system/info
echo ""
echo "=== 3. 引擎日志里最近的拦截/阻断记录 ==="
tail -40 /tmp/eng_run.log /tmp/novawaf.log 2>/dev/null | grep -iE "block|拦截|403|deny|system/info|attack|rule|hit" | tail -20
echo "=== 4. redis 最近告警/拦截事件 ==="
redis-cli -h 127.0.0.1 --scan --pattern 'novawaf:*' 2>/dev/null | head -20
