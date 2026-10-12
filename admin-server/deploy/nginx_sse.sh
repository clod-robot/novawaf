#!/bin/bash
SUDO() { printf '%s\n' 'MAO5201314sm' | sudo -S -p '' "$@"; }
CONF=/etc/nginx/conf.d/nac.conf
SUDO cp $CONF ${CONF}.bak_sse
SUDO cp /tmp/nac.conf.new $CONF
SUDO nginx -t 2>&1 && SUDO systemctl reload nginx 2>&1 && echo "RELOAD_OK" || echo "RELOAD_FAIL"
echo -n "SSE 直连验证: "; curl -sk -o /dev/null -w "%{http_code}\n" --max-time 3 "https://127.0.0.1/api/auth/monitor/stream" -H "Accept: text/event-stream"
