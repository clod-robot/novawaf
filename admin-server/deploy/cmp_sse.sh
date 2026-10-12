#!/bin/bash
JAR=/tmp/cj.txt
echo "=== A. 直连网关 8080（基线，8s） ==="
timeout 8 curl -s -N -b $JAR -H "Host: nac" http://127.0.0.1:8080/api/auth/monitor/stream 2>&1 | head -4
echo "--- 基线结束 ---"
echo "=== B. 经 WAF 8099（8s，带响应头确认 content-type） ==="
timeout 8 curl -s -N -i -b $JAR -H "Host: nac" http://127.0.0.1:8099/api/auth/monitor/stream 2>&1 | head -6
echo "--- WAF 结束 ---"
