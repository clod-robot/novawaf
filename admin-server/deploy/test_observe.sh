#!/bin/bash
BASE=http://127.0.0.1:18081
TOKEN=$(curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"Admin@2026"}' --max-time 5 | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
AUTH="Authorization: Bearer $TOKEN"
curl -s -X POST "$BASE/api/waf/apps/1/mode" -H "$AUTH" -H "Content-Type: application/json" -d '{"mode":"observe"}' >/dev/null
echo "set observe, wait 62s..."; sleep 62
echo "=== 观察模式连打5次正常请求 ==="
for i in 1 2 3 4 5; do
  echo -n "  #$i: "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: a.test" "http://127.0.0.1:8099/" --max-time 5
done
echo "=== 对比: 直连上游 18080 ==="
for i in 1 2 3; do echo -n "  direct#$i: "; curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:18080/" --max-time 5; done
echo "=== 引擎日志尾部 ==="
tail -15 /tmp/novawaf.log
# 恢复
curl -s -X POST "$BASE/api/waf/apps/1/mode" -H "$AUTH" -H "Content-Type: application/json" -d '{"mode":"protect"}' >/dev/null
echo "restored protect"
