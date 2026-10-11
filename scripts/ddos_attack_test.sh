#!/usr/bin/env bash
# NovaWAF DDoS 防护实测：模拟 HTTP Flood / 连接洪水，验证拦截与自动封禁
ENGINE_URL="http://127.0.0.1:18080/index.html"
echo "=== 1) 正常请求基线 ==="
code=$(curl -s -o /dev/null -w '%{http_code}' "$ENGINE_URL")
echo "正常请求 -> HTTP $code"

echo "=== 2) HTTP Flood：1 秒内发 3000 请求（阈值 req/s=1000）==="
ok=0; r429=0; err=0
for i in $(seq 1 3000); do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$ENGINE_URL" 2>/dev/null)
  case "$c" in
    200) ok=$((ok+1));;
    429) r429=$((r429+1));;
    *)   err=$((err+1));;
  esac
done
echo "  200(放行)=$ok  429(限流)=$r429  其它(被丢弃/错误)=$err"

echo "=== 3) 验证自动封禁：违规累计后，新连接应被直接丢弃 ==="
banned=0
for i in $(seq 1 20); do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "$ENGINE_URL" 2>/dev/null)
  # 连接被立即关闭会得到空/000
  if [ "$c" = "000" ] || [ -z "$c" ]; then banned=$((banned+1)); fi
done
echo "  封禁后探测 20 次，连接被直接丢弃次数=$banned"
echo "  （>0 说明触发了自动封禁，连接在 accept 阶段即被 DDoS 防护丢弃）"
