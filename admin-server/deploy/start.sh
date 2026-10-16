#!/bin/bash
# 启动 NovaWAF 后端。环境变量统一由 /etc/novawaf/novawaf.env 提供
# （含 NOVA_MYSQL_PASSWORD / NOVA_JWT_SECRET 等密钥，文件权限 600，不入库）。
# systemd 场景请改用 systemctl start novawaf-admin.service。
cd /home/mao/novawaf/admin-server
export JAVA_HOME=${JAVA_HOME:-/usr/local/jdk}
set -a
. /etc/novawaf/novawaf.env
set +a
pkill -f 'novawaf-admin.jar' 2>/dev/null
sleep 1
nohup $JAVA_HOME/bin/java -jar target/novawaf-admin.jar --server.port=18081 >/tmp/novawaf-admin.log 2>&1 &
echo "PID=$!"
sleep 8
echo "--- log tail ---"
tail -15 /tmp/novawaf-admin.log
echo "--- listen ---"
ss -tlnp 2>/dev/null | grep ':18081' || echo "18081 NOT listening"
