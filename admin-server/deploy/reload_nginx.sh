#!/bin/bash
echo "=== nginx 进程 ==="
ps -ef | grep '[n]ginx' | head
echo "=== 尝试 systemctl reload ==="
printf '%s\n' 'MAO5201314sm' | sudo -S -p '' systemctl reload nginx 2>&1 && echo "systemctl reload OK" || echo "systemctl reload FAILED"
echo "=== 若上面失败，直接 HUP master ==="
MPID=$(ps -ef | awk '/[n]ginx: master/{print $2; exit}')
echo "master pid=$MPID"
if [ -n "$MPID" ]; then printf '%s\n' 'MAO5201314sm' | sudo -S -p '' kill -HUP $MPID && echo "HUP sent"; fi
sleep 1
echo "=== 验证配置已生效(查 proxy_pass) ==="
grep -n "proxy_pass http://127.0.0.1:8099" /etc/nginx/conf.d/nac.conf | head
echo "=== 在线测试 ==="
echo -n "正常 /api/ 透传: "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/" --max-time 5
echo -n "SQLi 期望403:    "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/t?id=1'%20OR%20'1'='1" --max-time 5
echo -n "XSS  期望403:    "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/x?q=<script>alert(1)</script>" --max-time 5
