#!/bin/bash
BASE=http://127.0.0.1:18081
R="/usr/local/redis/bin/redis-cli -h 127.0.0.1"
TOKEN=$(curl -s -X POST $BASE/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"Admin@2026"}' --max-time 5 | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
AUTH="Authorization: Bearer $TOKEN"
APP=1  # a.test -> 127.0.0.1:18080
setmode(){ curl -s -X POST "$BASE/api/waf/apps/$APP/mode" -H "$AUTH" -H "Content-Type: application/json" -d "{\"mode\":\"$1\"}" >/dev/null; echo "  -> set mode=$1, version=$($R GET novawaf:apps:version)"; sleep 62; }
SQLI="/?id=1'%20OR%20'1'='1"

echo "=== [1] 防护模式 protect ==="; setmode protect
echo -n "  正常 : "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: a.test" "http://127.0.0.1:8099/" --max-time 4
echo -n "  攻击 : "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: a.test" "http://127.0.0.1:8099/$SQLI" --max-time 4

echo "=== [2] 观察模式 observe (攻击应放行,非403) ==="; setmode observe
echo -n "  正常 : "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: a.test" "http://127.0.0.1:8099/" --max-time 4
echo -n "  攻击 : "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: a.test" "http://127.0.0.1:8099/$SQLI" --max-time 4
echo "  事件(应记录到攻击):"; $R LRANGE novawaf:events -1 -1 | head -c 160; echo

echo "=== [3] 维护模式 maintenance (应全返回503维护页) ==="; setmode maintenance
echo -n "  正常 : "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: a.test" "http://127.0.0.1:8099/" --max-time 4
echo -n "  攻击 : "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: a.test" "http://127.0.0.1:8099/$SQLI" --max-time 4
echo "  维护页内容:"; curl -s -H "Host: a.test" "http://127.0.0.1:8099/" --max-time 4 | grep -o "系统维护中" | head -1

echo "=== 恢复 protect ==="; setmode protect
echo "  攻击应恢复403:"; curl -s -o /dev/null -w "  -> %{http_code}\n" -H "Host: a.test" "http://127.0.0.1:8099/$SQLI" --max-time 4
echo "ALL_DONE"
