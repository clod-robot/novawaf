#!/bin/bash
set -e
mkdir -p /var/www/novawaf-admin
rm -rf /var/www/novawaf-admin/*
cp -r /home/mao/novawaf/admin-web-dist/* /var/www/novawaf-admin/
chown -R www-data:www-data /var/www/novawaf-admin
cp /tmp/novawaf-admin.conf /etc/nginx/conf.d/novawaf-admin.conf
nginx -t
systemctl reload nginx
echo "NGINX_OK"
