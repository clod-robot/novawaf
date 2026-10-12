#!/bin/bash
TOK=$(curl -s -H "Content-Type: application/json" --data '{"username":"admin","password":"Admin@2026"}' http://127.0.0.1:18081/api/auth/login | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
H="-H Authorization:Bearer\ $TOK"
echo "=== geo 解析(8.8.8.8 应 US/美国, 114.114.114.1 应 CN/中国) ==="
curl -s -H "Authorization: Bearer $TOK" "http://127.0.0.1:18081/api/waf/iplist/geo/8.8.8.8"; echo
curl -s -H "Authorization: Bearer $TOK" "http://127.0.0.1:18081/api/waf/iplist/geo/114.114.114.1"; echo
echo "=== 新增黑名单 8.8.8.8 + 45.44.55.66 ==="
curl -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data '{"ip":"8.8.8.8","type":"black","note":"测试"}' http://127.0.0.1:18081/api/waf/iplist; echo
curl -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data '{"ip":"45.44.55.66","type":"black","note":"境外"}' http://127.0.0.1:18081/api/waf/iplist -o /dev/null -w "add=%{http_code}\n"
echo "=== 列表(应含 geo 标签) ==="
curl -s -H "Authorization: Bearer $TOK" "http://127.0.0.1:18081/api/waf/iplist?type=black" ; echo
echo "=== SSE 5s: 应收到 snapshot; 之后再 add 一条看 iplist 推送 ==="
(curl -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data '{"ip":"9.9.9.9","type":"white"}' http://127.0.0.1:18081/api/waf/iplist >/dev/null &)
curl -sN -m 6 "http://127.0.0.1:18081/api/waf/stream?token=$TOK" 2>&1 | grep -E 'event:(iplist|snapshot)' | head -4
echo "=== 白名单列表 ==="
curl -s -H "Authorization: Bearer $TOK" "http://127.0.0.1:18081/api/waf/iplist?type=white"; echo
echo "ALL_OK"