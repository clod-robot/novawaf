#!/bin/bash
H="Host: nac"
echo "=== 最终回归：3 项 ==="
# 1. 速度
t=$(curl -s -o /dev/null -w "%{time_total}" --max-time 5 -H "$H" http://127.0.0.1:8099/api/auth/captcha)
echo "[1] captcha 经WAF = ${t}s  (应 <0.05)"
# 2. 防护不退化
c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -H "$H" "http://127.0.0.1:8099/api/x?id=1%20UNION%20SELECT%20password")
echo "[2] SQLi 拦截 = $c  (应 403)"
# 3. SSE 不挂起
s=$(curl -s -o /dev/null -w "%{http_code} %{time_total}s" --max-time 4 -H "$H" -H "Accept: text/event-stream" http://127.0.0.1:8099/api/auth/monitor/stream)
echo "[3] SSE 经WAF = $s  (应即时返回，不等到4s超时)"
