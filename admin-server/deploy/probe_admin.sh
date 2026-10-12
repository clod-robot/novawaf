#!/bin/bash
echo "=== 管理端 nginx 站点配置文件 ==="
grep -rl "novawaf-admin\|18081" /etc/nginx/ 2>/dev/null | head
echo "=== 管理进程 ==="
ps -ef | grep -E "novawaf-admin.jar|18081" | grep -v grep | head -2
echo "=== 启动脚本 ==="
ls -la /tmp/admin_start.sh 2>/dev/null && head -5 /tmp/admin_start.sh
echo "=== 现管理端 server 块(找 api 反代) ==="
grep -rn "proxy_pass\|location\|proxy_buffering\|server_name" /etc/nginx/conf.d/*.conf 2>/dev/null | grep -iE "18081|novawaf-admin" | head