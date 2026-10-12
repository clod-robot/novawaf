#!/bin/bash
TOK=$(curl -s --max-time 5 -H "Content-Type: application/json" \
  --data '{"username":"admin","password":"admin123"}' http://127.0.0.1:18081/api/auth/login \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
echo "token=${TOK:0:16}..."
echo "=== events ==="
curl -s --max-time 5 -H "Authorization: Bearer $TOK" "http://127.0.0.1:18081/api/waf/events?limit=10" 2>&1 | head -c 2500; echo
echo "=== rules ==="
curl -s --max-time 5 -H "Authorization: Bearer $TOK" "http://127.0.0.1:18081/api/waf/rules" 2>&1 | head -c 2500; echo
