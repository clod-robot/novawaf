#!/bin/bash
SUDO() { printf '%s\n' 'MAO5201314sm' | sudo -S -p '' "$@"; }
CONF=/etc/nginx/conf.d/nac.conf
SUDO cp /tmp/nac.conf.new $CONF
SUDO nginx -t 2>&1 && SUDO systemctl reload nginx 2>&1 && echo "RELOAD_OK" || echo "RELOAD_FAIL"
echo "=== 经 HTTPS→WAF 拉 SSE（即时响应不挂起即可） ==="
curl -sk -i --max-time 4 https://127.0.0.1/api/auth/monitor/stream -H "Accept: text/event-stream" 2>&1 | head -3
