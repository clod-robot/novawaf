#!/bin/bash
BASE=http://127.0.0.1:18081
TOKEN=$(curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"Admin@2026"}' --max-time 5 | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
AUTH="Authorization: Bearer $TOKEN"
echo "非法域名:"; curl -s -X PUT "$BASE/api/waf/apps/1" -H "$AUTH" -H "Content-Type: application/json" -d '{"host":"https://x.com/a","upstreamHost":"127.0.0.1","upstreamPort":18080}' --max-time 5; echo
echo "端口80:    "; curl -s -X PUT "$BASE/api/waf/apps/1" -H "$AUTH" -H "Content-Type: application/json" -d '{"host":"a.test","upstreamHost":"127.0.0.1","upstreamPort":80}' --max-time 5; echo
echo "正常修改:  "; curl -s -X PUT "$BASE/api/waf/apps/2" -H "$AUTH" -H "Content-Type: application/json" -d '{"name":"B","host":"b.test","upstreamHost":"127.0.0.1","upstreamPort":18081,"statsEnabled":true}' --max-time 5; echo
