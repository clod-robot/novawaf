#!/bin/bash
echo "=== 1. SSE 经 WAF(8099) 流式透传：应立即返回响应头（不缓冲挂起） ==="
curl -s -N -i --max-time 5 http://127.0.0.1:8099/api/auth/monitor/stream -H "Host: nac" 2>&1 | head -8
echo ""
echo "=== 2. 普通 API 经 WAF 正常转发 ==="
curl -s -o /dev/null -w "http=%{http_code} time=%{time_total}s\n" --max-time 5 http://127.0.0.1:8099/api/auth/captcha -H "Host: nac"
echo "=== 3. 攻击仍被拦截（防护不退化） ==="
curl -s -o /dev/null -w "http=%{http_code}\n" --max-time 5 "http://127.0.0.1:8099/api/test?id=1%20AND%201=1%20UNION%20SELECT" -H "Host: nac"
echo "=== 4. WS 升级握手经 WAF（应返回 101，不挂起） ==="
curl -s -i --max-time 4 -H "Host: nac" -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "http://127.0.0.1:8099/ws/terminal" 2>&1 | head -5
