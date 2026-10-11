#!/usr/bin/env bash
ENGINE_URL="http://127.0.0.1:18080/index.html"
echo "=== 正常基线 ==="
curl -s -o /dev/null -w 'HTTP %{http_code}\n' "$ENGINE_URL"

echo "=== 并发洪水 (ab -n 8000 -c 200) 单IP冲击，必超 req/s=1000 ==="
ab -n 8000 -c 200 "$ENGINE_URL" 2>&1 | grep -E 'Complete requests|Failed requests|Non-2xx responses'

echo "=== 洪水后：探测是否被自动封禁（连接应被直接丢弃=000）==="
drop=0; ok2=0
for i in $(seq 1 30); do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "$ENGINE_URL" 2>/dev/null)
  if [ "$c" = "000" ] || [ -z "$c" ]; then drop=$((drop+1)); else ok2=$((ok2+1)); fi
done
echo "  30次探测：被丢弃(已封禁)=$drop  正常响应=$ok2"
