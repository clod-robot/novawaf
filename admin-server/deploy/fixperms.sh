#!/bin/bash
echo MAO5201314sm | sudo -S chown -R nginx:nginx /var/www/novawaf-admin
echo MAO5201314sm | sudo -S find /var/www/novawaf-admin -type d -exec chmod 755 {} \;
echo MAO5201314sm | sudo -S find /var/www/novawaf-admin -type f -exec chmod 644 {} \;
echo MAO5201314sm | sudo -S systemctl reload nginx
ls -ld /var/www/novawaf-admin /var/www/novawaf-admin/assets
echo "PERMS_FIXED"
