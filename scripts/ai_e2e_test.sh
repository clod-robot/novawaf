#!/usr/bin/env bash
# NovaWAF AI 端到端实测：
#  A) AI 抓规则漏判的变种攻击（可疑预筛命中 → AI 拦截）
#  B) AI 超时/不可用 → 自动降级，服务不中断（fail-closed）
set -u
URL="http://127.0.0.1:18080/"

pkill -f novawaf-engine 2>/dev/null
pkill -f mock_llm.py 2>/dev/null
sleep 0.5

echo "=== A) 启用 AI（mock 返回 block=true）：AI 抓可疑变种攻击 ==="
python3 /tmp/mock_llm.py block 18090 >/tmp/llm.log 2>&1 &
sleep 1
NOVAAI_ENABLE=1 NOVAAI_ENDPOINT="http://127.0.0.1:18090/v1/chat/completions" \
  NOVAAI_MODEL=mock NOVAAI_TIMEOUT_MS=800 \
  nohup /tmp/novawaf-engine 18080 4 >/tmp/engine.log 2>&1 </dev/null &
sleep 1.5

# 构造一个规则引擎可能漏掉、但含可疑字符(;)的变种 payload
echo -n "  可疑变种请求 ?x=;curl http://evil -> HTTP "
curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:18080/?x=;curl%20http://evil"
echo -n "  正常请求 /index.html -> HTTP "
curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:18080/index.html"

pkill -f novawaf-engine 2>/dev/null
pkill -f mock_llm.py 2>/dev/null
sleep 0.5

echo "=== B) 降级测试：AI 端点不存在（不可用）→ 引擎仍正常工作 ==="
NOVAAI_ENABLE=1 NOVAAI_ENDPOINT="http://127.0.0.1:19999/v1/chat/completions" \
  NOVAAI_TIMEOUT_MS=500 \
  nohup /tmp/novawaf-engine 18080 4 >/tmp/engine2.log 2>&1 </dev/null &
sleep 1.5
echo -n "  AI 挂掉时正常请求 -> HTTP "
curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 "http://127.0.0.1:18080/index.html"
echo -n "  AI 挂掉时攻击请求 -> HTTP "
curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 "http://127.0.0.1:18080/?id=1'%20or%20'1'='1"
echo "  （200=降级放行正常流量；403=规则仍拦截攻击，证明 fail-closed 降级正常）"

pkill -f novawaf-engine 2>/dev/null
