#!/usr/bin/env bash
# NovaWAF 引擎攻防测试脚本
set +e
pkill -f novawaf-engine 2>/dev/null
sleep 0.3
nohup /tmp/novawaf-engine 18080 2 >/tmp/engine.log 2>&1 &
sleep 1

echo "=== 测试1: 正常请求 (期望 200) ==="
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:18080/index.html?q=hello'

echo "=== 测试2: SQL注入 (期望 403) ==="
curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:18080/?id=1'%20or%20'1'='1"

echo "=== 测试3: XSS (期望 403) ==="
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:18080/?q=%3Cscript%3Ealert(1)%3C/script%3E'

echo "=== 测试4: 路径穿越 (期望 403) ==="
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:18080/?f=../../etc/passwd'

echo "=== 测试5: 编码绕过SQLi (期望 403) ==="
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:18080/?q=%253cscript%253e'

echo "=== 引擎拦截日志 ==="
cat /tmp/engine.log
