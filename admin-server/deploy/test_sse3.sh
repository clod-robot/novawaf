#!/bin/bash
echo "=== 清掉可能的登录锁键 ==="
for k in $(redis-cli -h 127.0.0.1 --scan --pattern 'nova:fail:*' 2>/dev/null); do redis-cli -h 127.0.0.1 del "$k" >/dev/null 2>&1; done
echo "=== 登录 (admin / Admin@2026) ==="
LOGIN=$(curl -s --max-time 8 -H "Content-Type: application/json" \
  --data '{"username":"admin","password":"Admin@2026"}' http://127.0.0.1:18081/api/auth/login)
echo "$LOGIN" | head -c 160; echo
TOK=$(echo "$LOGIN" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -z "$TOK" ] && { echo "登录失败"; exit 1; }
echo "token=${TOK:0:16}..."
echo "=== 直连后端 SSE 6s ==="
curl -sN -m 6 "http://127.0.0.1:18081/api/waf/stream?token=$TOK" 2>&1 | head -c 800
echo ""
echo "=== 经 nginx:9000 SSE 5s ==="
curl -sN -m 5 "http://127.0.0.1:9000/api/waf/stream?token=$TOK" 2>&1 | head -c 400
echo ""
echo "SSE_OK"
