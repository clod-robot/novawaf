#!/bin/bash
# 启动测试上游（若未运行）
if ! ss -tln 2>/dev/null | grep -q ':18080 '; then
  cd /tmp && nohup python3 -m http.server 18080 >/tmp/up18080.log 2>&1 &
  sleep 1
fi
echo "up 18080: $(ss -tln 2>/dev/null | grep ':18080 ' | head -1)"
# 通过引擎发请求（带 UA + Referer）
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -H "Host: a.test" -A "Mozilla/5.0 (Windows NT 10.0) NovaWAF-Test/$i" \
       -e "https://example.org/page$i" "http://127.0.0.1:8099/" --max-time 3
done
# 一条攻击请求（应 403）
curl -s -o /dev/null -H "Host: a.test" -A "sqlmap/1.5" "http://127.0.0.1:8099/?id=1%27%20OR%20%271%27=%271" --max-time 3
sleep 2
echo "=== novawaf:access 长度 ==="
/usr/local/redis/bin/redis-cli -h 127.0.0.1 LLEN novawaf:access
echo "=== 最近 3 条 ==="
/usr/local/redis/bin/redis-cli -h 127.0.0.1 LRANGE novawaf:access -3 -1
