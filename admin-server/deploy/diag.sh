#!/bin/bash
echo "=== nginx 加载的 9000 server 配置 ==="
echo MAO5201314sm | sudo -S nginx -T 2>/dev/null | grep -A6 'listen 9000'
echo "=== 文件存在性(www-data 读取测试) ==="
F=/var/www/novawaf-admin/assets/index-d5jWVBFW.js
ls -la "$F"
echo MAO5201314sm | sudo -S -u www-data test -r "$F" && echo "WWW_DATA_READABLE" || echo "WWW_DATA_CANNOT_READ"
echo "=== /var/www/novawaf-admin 目录权限 ==="
ls -ld /var/www/novawaf-admin /var/www/novawaf-admin/assets
