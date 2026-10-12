#!/bin/bash
JAR=/tmp/cj.txt; rm -f $JAR
# 尝试登录获取会话（常见账号）；失败则退出
for cred in '{"username":"admin","password":"admin123"}' '{"username":"admin","password":"Admin@123"}'; do
  curl -s -c $JAR -b $JAR -o /dev/null -w "login=%{http_code}\n" --max-time 5 \
    -H "Content-Type: application/json" -H "Host: nac" \
    --data "$cred" http://127.0.0.1:8099/api/auth/login
  grep -q 'nac' $JAR 2>/dev/null && break
done
echo "=== 带会话经 WAF 拉 SSE 流（5 秒，看是否有 data: 持续输出） ==="
curl -s -N -b $JAR -H "Host: nac" --max-time 5 http://127.0.0.1:8099/api/auth/monitor/stream 2>&1 | head -6
echo "=== 流结束（若上面有 data: 行即证明经 WAF 流式透传成功） ==="
