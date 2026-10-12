#!/bin/bash
# 基准：直连网关 vs 经WAF vs nginx→WAF，每个路径多次取均值
bench() {
  local name="$1"; shift
  local sum=0 cnt=6
  for i in $(seq 1 $cnt); do
    t=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 "$@")
    sum=$(awk "BEGIN{print $sum+$t}")
  done
  awk "BEGIN{printf \"%-22s 平均=%.3fs  (单次样例见下)\n\", \"$name\", $sum/$cnt}"
  curl -s -o /dev/null -w "   单次: dns=%{time_namelookup} conn=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total} code=%{http_code}\n" --max-time 10 "$@"
}
H="Host: nac"
echo "===== 接口：/api/auth/captcha ====="
bench "直连网关 8080"      -H "$H" "http://127.0.0.1:8080/api/auth/captcha"
bench "经WAF 8099"         -H "$H" "http://127.0.0.1:8099/api/auth/captcha"
bench "nginx→WAF(https)"   "https://127.0.0.1/api/auth/captcha" -k
echo "===== 接口：/api/auth/monitor (轻量GET) ====="
bench "直连 8080"  -H "$H" "http://127.0.0.1:8080/api/auth/info"
bench "经WAF 8099" -H "$H" "http://127.0.0.1:8099/api/auth/info"
