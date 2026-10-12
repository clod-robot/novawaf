#!/bin/bash
R="/usr/local/redis/bin/redis-cli -h 127.0.0.1"
# 修正 NAC 应用：host 必须是纯主机名(与 nginx proxy_set_header Host 一致)，上游指向 nac-gateway
FIXED='[{"default":false,"host":"a.test","id":1,"name":"A","statsEnabled":true,"upstreamHost":"127.0.0.1","upstreamPort":18080},{"default":false,"host":"b.test","id":2,"name":"B","statsEnabled":false,"upstreamHost":"127.0.0.1","upstreamPort":18081},{"default":false,"host":"nac","id":3,"name":"NAC","statsEnabled":true,"upstreamHost":"127.0.0.1","upstreamPort":8080}]'
$R SET novawaf:apps "$FIXED"
$R INCR novawaf:apps:version
echo "=== 修正后 ==="
$R GET novawaf:apps
$R GET novawaf:apps:version
sleep 2
echo "=== 验证 ==="
echo -n "WAF 8099 Host:nac / : "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: nac" "http://127.0.0.1:8099/" --max-time 5
echo -n "HTTPS /api/ 透传   : "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/" --max-time 5
echo -n "HTTPS SQLi 拦截403 : "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/t?id=1'%20OR%20'1'='1" --max-time 5
