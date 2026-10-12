#!/bin/bash
echo "=== 1) /nac/ 首页返回内容(前30行) ==="
curl -sk "https://127.0.0.1/nac/" --max-time 5 | head -30
echo
echo "=== 2) 各路径 HTTP 状态 ==="
echo -n "/nac/          : "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/nac/" --max-time 5
echo -n "/api/          : "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/" --max-time 5
echo -n "WAF直连8099 /  : "; curl -s -o /dev/null -w "%{http_code}\n" -H "Host: nac" "http://127.0.0.1:8099/" --max-time 5
echo
echo "=== 3) 引擎进程 ==="
ps -ef | grep '[n]ovawaf' | head
echo
echo "=== 4) novawaf:apps 内容 ==="
/usr/local/redis/bin/redis-cli -h 127.0.0.1 GET novawaf:apps
echo
echo "=== 5) 引擎最近日志 ==="
tail -20 /tmp/novawaf.log 2>/dev/null || tail -20 ~/novawaf.log 2>/dev/null
echo
echo "=== 6) 全局搜 '维护/maintenance' 页面 ==="
printf '%s\n' 'MAO5201314sm' | sudo -S -p '' grep -rl "正在维护\|maintenance\|under maintenance" /var/www /usr/share/nginx /etc/nginx 2>/dev/null | head
