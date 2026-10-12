#!/bin/bash
R="/usr/local/redis/bin/redis-cli -h 127.0.0.1"
echo "=== 当前 novawaf:apps ==="
$R GET novawaf:apps
echo
echo "=== A) 后台管理: 登录拿token ==="
TOK=$(curl -s -X POST http://127.0.0.1:18081/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"Admin@2026"}' --max-time 5)
echo "$TOK" | head -c 120; echo
TOKEN=$(echo "$TOK" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
echo "token len=${#TOKEN}"
echo
echo "=== B) 后台管理: GET /api/waf/apps(应200) ==="
curl -s -o /dev/null -w "  -> %{http_code}\n" http://127.0.0.1:18081/api/waf/apps -H "Authorization: Bearer $TOKEN" --max-time 5
echo
echo "=== C) 访问被防护站点(经nginx→WAF→gateway), 看返回码 ==="
echo -n "  正常 /api/        : "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/" --max-time 5
echo -n "  带攻击 /api/?id=1': "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/?id=1'%20OR%201=1" --max-time 5
echo
echo "=== D) 直连WAF(8099)用不同Host看匹配 ==="
for H in nac a.test b.test example.com 192.168.100.2; do
  echo -n "  Host=$H -> "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: $H" "http://127.0.0.1:8099/" --max-time 4
done
