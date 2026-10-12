#!/bin/bash
echo "=== 引擎动态依赖 ==="
ldd /tmp/novawaf-engine 2>/dev/null | grep -iE "yara|not found"
echo "=== 前端 dist 部署位置 ==="
find /var/www /usr/share/nginx /home/mao -maxdepth 4 -name "index.html" -path "*dist*" 2>/dev/null | head
find /home/mao/novawaf/admin-web -maxdepth 2 -name "index.html" 2>/dev/null | head
echo "=== nginx 站点根 ==="
grep -rhoE "root[^;]*;" /etc/nginx/conf.d/*.conf 2>/dev/null | sort -u | head
echo "=== 已部署前端目录 ==="
ls -d /var/www/nac* /var/www/html/nac* 2>/dev/null
