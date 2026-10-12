#!/bin/bash
TOK=$(curl -s -H "Content-Type: application/json" --data '{"username":"admin","password":"Admin@2026"}' http://127.0.0.1:18081/api/auth/login | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -s -X PUT -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  --data '{"enabled":false,"host":"127.0.0.1","port":514,"protocol":"udp","facility":"local0","tag":"novawaf","minLevel":"info","forwardAlerts":true,"forwardRuntime":true}' \
  http://127.0.0.1:18081/api/waf/syslog -o /dev/null -w "disable=%{http_code}\n"
curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:18081/api/waf/syslog | head -c 200; echo