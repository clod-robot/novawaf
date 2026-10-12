#!/bin/bash
echo "=== /var/www/novawaf-admin/index.html 入口 ==="
grep -o 'index-[a-zA-Z0-9_]*\.js' /var/www/novawaf-admin/index.html
echo "=== ~/novawaf/admin-web-dist/index.html 入口 ==="
grep -o 'index-[a-zA-Z0-9_]*\.js' /home/mao/novawaf/admin-web-dist/index.html
echo "=== 本地tar解出的 /tmp 检查 ==="
ls -la /tmp/dist.tgz
