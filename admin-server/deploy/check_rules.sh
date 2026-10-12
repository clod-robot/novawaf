#!/bin/bash
echo "=== 引擎是否把规则写进了 Redis? ==="
for k in novawaf:rules novawaf:rules:version; do
  T=$(redis-cli -h 127.0.0.1 --no-raw TYPE "$k" 2>/dev/null)
  L=$(redis-cli -h 127.0.0.1 --no-raw STRLEN "$k" 2>/dev/null)
  echo "key=$k type=$T strlen=$L"
done
echo "=== novawaf:rules 前 400 字符 ==="
redis-cli -h 127.0.0.1 --no-raw GET novawaf:rules 2>/dev/null | head -c 400
echo ""
echo "=== 相关键一览 ==="
redis-cli -h 127.0.0.1 --scan --pattern 'novawaf:*' 2>/dev/null | head -30