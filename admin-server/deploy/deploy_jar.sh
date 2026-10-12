#!/bin/bash
echo "[1] 替换 jar 并重启后端"
cp -f /tmp/novawaf-admin.jar /home/mao/novawaf/admin-server/target/novawaf-admin.jar
pkill -f 'novawaf-admin.jar' 2>/dev/null; sleep 2
nohup bash /tmp/admin_start.sh >/tmp/novawaf-admin.log 2>&1 &
echo "  等待启动..."
for i in $(seq 1 40); do
  sleep 2
  if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/api/auth/login -X POST -H 'Content-Type: application/json' --data '{"username":"x","password":"x"}' 2>/dev/null | grep -q 200; then
    echo "  后端就绪 (${i}x2s)"; break
  fi
done
echo "[2] 验证规则接口(应返回 10 条)"
TOK=$(curl -s -H "Content-Type: application/json" --data '{"username":"admin","password":"Admin@2026"}' http://127.0.0.1:18081/api/auth/login | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:18081/api/waf/rules | head -c 500
echo ""
echo "[3] 触发一条自定义规则: pattern=union select"
curl -s -o /dev/null -w "sqli_custom=%{http_code}\n" "http://127.0.0.1:8099/?q=1%20union%20select%201" -H "Host: nac"
echo "JAR_DONE"
