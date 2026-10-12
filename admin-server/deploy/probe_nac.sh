#!/bin/bash
echo "=== nac-gateway 8080 ==="
curl -s -o /dev/null -w "GET / -> %{http_code}\n" http://127.0.0.1:8080/ --max-time 4
curl -s -o /dev/null -w "GET /actuator/health -> %{http_code}\n" http://127.0.0.1:8080/actuator/health --max-time 4
echo
echo "=== nginx 站点 ==="
grep -RniE "server_name|proxy_pass|listen" /etc/nginx/ 2>/dev/null | grep -viE "^[^:]*:[0-9]+:#" | head -50
