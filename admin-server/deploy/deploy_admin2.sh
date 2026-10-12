#!/bin/bash
set -e
PW=MAO5201314sm
echo "[1/4] 部署后端 jar"
cp -f /tmp/novawaf-admin.jar /home/mao/novawaf/admin-server/target/novawaf-admin.jar
pkill -f 'novawaf-admin.jar' 2>/dev/null || true
sleep 2
nohup bash /tmp/admin_start.sh >/tmp/novawaf-admin.log 2>&1 &
echo "  后端重启中..."

echo "[2/4] 部署前端 dist"
cd /home/mao && rm -rf /tmp/distnew && mkdir -p /tmp/distnew
tar xzf /tmp/admin-web.tar.gz -C /tmp/distnew
echo "$PW" | sudo -S -p '' bash -c 'rm -rf /var/www/novawaf-admin/* && cp -r /tmp/distnew/dist/. /var/www/novawaf-admin/ && chown -R nginx:nginx /var/www/novawaf-admin' >/dev/null 2>&1

echo "[3/4] 更新 nginx 配置(SSE)"
echo "$PW" | sudo -S -p '' cp /tmp/novawaf-admin.conf /etc/nginx/conf.d/novawaf-admin.conf >/dev/null 2>&1
echo "$PW" | sudo -S -p '' nginx -t 2>&1 | tail -2

echo "[4/4] reload nginx"
for pid in $(ps -ef | grep '[n]ginx: master' | awk '{print $2}'); do
  echo "$PW" | sudo -S -p '' kill -HUP "$pid" 2>/dev/null && echo "  HUP master $pid"
done
echo "DONE_DEPLOY"
