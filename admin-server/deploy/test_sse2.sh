#!/bin/bash
echo "=== 登录获取 token ==="
LOGIN=$(curl -s --max-time 8 -H "Content-Type: application/json" \
  --data '{"username":"admin","password":"admin123"}' http://127.0.0.1:18081/api/auth/login)
echo "$LOGIN" | head -c 200; echo
TOK=$(echo "$LOGIN" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
echo "token=${TOK:0:20}..."
if [ -z "$TOK" ]; then echo "登录失败，退出"; exit 1; fi

echo "=== 订阅 SSE 流 6 秒（应持续收到 data: 行）==="
curl -sN -m 6 -H "Accept: text/event-stream" \
  "http://127.0.0.1:18081/api/waf/stream?token=$TOK" 2>&1 | head -c 1200
echo ""
echo "=== 经 nginx(9000) 订阅 SSE ==="
curl -sN -m 6 "http://127.0.0.1:9000/api/waf/stream?token=$TOK" 2>&1 | head -c 600
echo ""
echo "=== 触发一次攻击事件（应经 SSE 实时出现）==="
curl -s -o /dev/null -w "sqli=%{http_code}\n" "http://127.0.0.1:8099/api/x?q=1%20UNION%20SELECT%20password%20FROM%20users" -H "Host: nac"
echo "SSE_DONE"
