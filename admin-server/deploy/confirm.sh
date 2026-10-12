#!/bin/bash
H="Host: nac"
t() { printf "%-34s -> " "$1"; curl -s -o /dev/null -w "%{http_code}\n" --max-time 3 -H "$H" "http://127.0.0.1:8099$1"; }
t "/api/auth/system/info"     # 含 system -> 预测 403
t "/api/auth/public/info"     # 含 public -> 预测 403
t "/api/auth/sys/info"        # 不含 -> 预测放行
t "/api/auth/pub/info"        # 不含 -> 预测放行
echo "若 system/public 都 403 而 sys/pub 放行，则确认是 XXE 裸词误报"
