#!/bin/bash
JAR=/tmp/adj.txt; rm -f $JAR
curl -s -c $JAR -o /dev/null -w "login=%{http_code}\n" --max-time 5 \
  -H "Content-Type: application/json" \
  --data '{"username":"admin","password":"admin123"}' http://127.0.0.1:18081/api/auth/login
echo "=== events ==="
curl -s -b $JAR --max-time 5 "http://127.0.0.1:18081/api/waf/events?limit=10" 2>&1 | head -c 2000; echo
echo "=== logs ==="
curl -s -b $JAR --max-time 5 "http://127.0.0.1:18081/api/waf/logs?limit=10" 2>&1 | head -c 2000; echo
