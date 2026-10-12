#!/bin/bash
BASE=http://127.0.0.1:18081
TOKEN=$(curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"Admin@2026"}' --max-time 5 | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
AUTH="Authorization: Bearer $TOKEN"
echo "=== 1) 修改应用 id=1(保持原值，应200并触发版本+) ==="
curl -s -o /dev/null -w "PUT /apps/1 -> %{http_code}\n" -X PUT "$BASE/api/waf/apps/1" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"name":"A","host":"a.test","upstreamHost":"127.0.0.1","upstreamPort":18080,"statsEnabled":true}' --max-time 5
echo "=== 2) 非法域名应被拒(应400) ==="
curl -s -o /dev/null -w "PUT bad-host -> %{http_code}\n" -X PUT "$BASE/api/waf/apps/1" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"name":"A","host":"https://x.com/a","upstreamHost":"127.0.0.1","upstreamPort":18080}' --max-time 5
echo "=== 3) 上游端口80应被拒(应400) ==="
curl -s -o /dev/null -w "PUT port80 -> %{http_code}\n" -X PUT "$BASE/api/waf/apps/1" -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"name":"A","host":"a.test","upstreamHost":"127.0.0.1","upstreamPort":80}' --max-time 5
echo "=== 4) apps:version 应已递增 ==="
/usr/local/redis/bin/redis-cli -h 127.0.0.1 GET novawaf:apps:version
