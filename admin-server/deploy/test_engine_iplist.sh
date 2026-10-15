#!/bin/bash
TOK=$(curl -s -H "Content-Type: application/json" --data '{"username":"admin","password":"Admin@2026"}' http://127.0.0.1:18081/api/auth/login | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
H="Authorization: Bearer $TOK"
add() { curl -s -X POST -H "$H" -H "Content-Type: application/json" --data "{\"ip\":\"127.0.0.1\",\"type\":\"$1\",\"note\":\"enginetest\"}" http://127.0.0.1:18081/api/waf/iplist >/dev/null; }
del() { curl -s -X DELETE -H "$H" "http://127.0.0.1:18081/api/waf/iplist?type=$1&ip=127.0.0.1" >/dev/null; }
get() { curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:8099$1" -H "Host: a.test"; }

# 清理先
del black; del white; sleep 4
echo "基线 正常GET      -> $(get /)  (期望200)"
echo "基线 SQLi         -> $(get "/?id=1'%20OR%20'1'='1")  (期望403)"

echo "--- 127.0.0.1 加入黑名单 ---"
add black; sleep 4
echo "黑名单 正常GET    -> $(get /)  (期望403)"
echo "黑名单 SQLi       -> $(get "/?id=1'%20OR%20'1'='1")  (期望403)"

echo "--- 移出黑名单, 加入白名单 ---"
del black; add white; sleep 4
echo "白名单 正常GET    -> $(get /)  (期望200)"
echo "白名单 SQLi(应放行)-> $(get "/?id=1'%20OR%20'1'='1")  (期望200, 白名单绕过检测)"

echo "--- 移出白名单(清理恢复) ---"
del white; sleep 4
echo "恢复后 SQLi       -> $(get "/?id=1'%20OR%20'1'='1")  (期望403)"
echo "TEST_DONE"