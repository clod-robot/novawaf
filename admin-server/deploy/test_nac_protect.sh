#!/bin/bash
H="http://127.0.0.1:8099"
echo "=== 热加载后引擎日志(是否识别到 nac) ==="
grep -i "Apps:" /tmp/novawaf.log | tail -3
echo
echo "=== 1) 正常请求(应透传到 nac-gateway，非 403) ==="
curl -s -o /dev/null -w "Host:nac GET /              -> %{http_code}\n" -H "Host: nac" "$H/" --max-time 5
echo "=== 2) SQLi 攻击(应被 WAF 拦截 403) ==="
curl -s -o /dev/null -w "Host:nac SQLi                -> %{http_code}\n" -H "Host: nac" "$H/?id=1%27%20OR%20%271%27=%271" --max-time 5
echo "=== 3) XSS 攻击(应 403) ==="
curl -s -o /dev/null -w "Host:nac XSS                 -> %{http_code}\n" -H "Host: nac" "$H/?q=%3Cscript%3Ealert(1)%3C/script%3E" --max-time 5
echo "=== 4) 路径穿越(应 403) ==="
curl -s -o /dev/null -w "Host:nac path-traversal      -> %{http_code}\n" -H "Host: nac" "$H/../../etc/passwd" --max-time 5
echo
echo "=== 最近攻击事件(novawaf:events 末条) ==="
/usr/local/redis/bin/redis-cli -h 127.0.0.1 LRANGE novawaf:events -2 -1
