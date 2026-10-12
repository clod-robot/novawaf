#!/bin/bash
echo "=== which redis-cli ==="
which redis-cli 2>&1
echo "=== ping ==="
redis-cli -h 127.0.0.1 ping 2>&1
echo "=== 启动脚本里的 redis 环境变量 ==="
grep -i redis /tmp/admin_start.sh 2>/dev/null
echo "=== systemctl 环境或进程环境 ==="
PID=$(pgrep -f novawaf-admin.jar | head -1)
cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'REDIS|REDIS_PASSWORD' 
echo "=== 试常用密码 ==="
for pw in "" "novawaf" "redis" "123456" "MAO5201314sm"; do
  R=$(redis-cli -h 127.0.0.1 ${pw:+-a "$pw"} ping 2>&1 | head -1)
  echo "pw=[$pw] -> $R"
done