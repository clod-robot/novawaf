#!/bin/bash
TOK=$(curl -s -H "Content-Type: application/json" --data '{"username":"admin","password":"Admin@2026"}' http://127.0.0.1:18081/api/auth/login | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
echo "=== /api/waf/rules 真实返回(前端拿到的就是这个) ==="
curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:18081/api/waf/rules | head -c 800
echo ""
echo "=== /api/waf/apps ==="
curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:18081/api/waf/apps | head -c 300
echo ""