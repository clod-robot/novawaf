#!/bin/bash
# 启动 NovaWAF 后端(异步审计不影响主流程)
cd /home/mao/novawaf/admin-server
export JAVA_HOME=/usr/local/jdk
export NOVA_MYSQL_HOST=127.0.0.1
export NOVA_MYSQL_DB=novawaf_admin
export NOVA_MYSQL_USER=waf_admin
export NOVA_MYSQL_PASSWORD='K0SXBgdU8lyvI3eD'
export NOVA_REDIS_HOST=127.0.0.1
export NOVA_JWT_SECRET='NovaWAF-JWT-Secret-2026-Please-Rotate-Me-32chars'
export NOVA_ADMIN_PASSWORD='Admin@2026'
pkill -f 'novawaf-admin.jar' 2>/dev/null
sleep 1
nohup $JAVA_HOME/bin/java -jar target/novawaf-admin.jar --server.port=18081 >/tmp/novawaf-admin.log 2>&1 &
echo "PID=$!"
sleep 8
echo "--- log tail ---"
tail -15 /tmp/novawaf-admin.log
echo "--- listen ---"
ss -tlnp 2>/dev/null | grep ':8081' || echo "8081 NOT listening"
