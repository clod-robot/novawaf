#!/bin/bash
H="Host: nac"
t() { printf "%-40s -> " "$1"; curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" --max-time 4 -H "$H" "http://127.0.0.1:8099$1"; }
t "/api/auth/system/info"
t "/api/auth/info"
t "/api/auth/system"
t "/api/auth/system/xyz"
t "/api/auth/sys/info"
t "/api/foo/system/info"
t "/api/auth/login"
t "/api/auth/captcha"
echo "--- 带浏览器 UA / Referer ---"
curl -s -o /dev/null -w "UA+Referer: %{http_code}\n" --max-time 4 -H "$H" \
  -H "User-Agent: Mozilla/5.0" -H "Referer: https://192.168.100.2/" \
  "http://127.0.0.1:8099/api/auth/system/info"
