#!/bin/bash
TOK=$(curl -s -H "Content-Type: application/json" --data '{"username":"admin","password":"Admin@2026"}' http://127.0.0.1:18081/api/auth/login | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
echo "=== geo 标签(应中文: 美国/中国) ==="
curl -s -H "Authorization: Bearer $TOK" "http://127.0.0.1:18081/api/waf/iplist?type=black&q=8.8.8.8"; echo
echo "=== SSE: 先订阅, 1.5s 后新增一条, 抓 iplist 事件 ==="
( sleep 1.5; curl -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data '{"ip":"1.1.1.1","type":"black","note":"sse测试"}' http://127.0.0.1:18081/api/waf/iplist >/dev/null ) &
curl -sN -m 6 "http://127.0.0.1:18081/api/waf/stream?token=$TOK" 2>&1 | grep -E 'event:(iplist|snapshot)' | sort | uniq -c
echo "DONE"