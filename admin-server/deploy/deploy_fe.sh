#!/bin/bash
echo MAO5201314sm | sudo -S -p '' bash -c 'rm -rf /var/www/novawaf-admin/* && tar -xf /tmp/novawaf-dist.tar -C /var/www/novawaf-admin && chown -R nginx:nginx /var/www/novawaf-admin'
echo "DEPLOY_OK"
ls /var/www/novawaf-admin | head
