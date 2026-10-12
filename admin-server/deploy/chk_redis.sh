#!/bin/bash
echo "=== redis 所有 novawaf 键 ==="
redis-cli -h 127.0.0.1 --scan --pattern 'novawaf*' 2>/dev/null
echo "=== 事件/告警 list 最新 5 条 ==="
for k in novawaf:events novawaf:alerts novawaf:attack:log; do
  echo "--- $k ---"; redis-cli -h 127.0.0.1 lrange "$k" 0 4 2>/dev/null
done
echo "=== 引擎日志全量尾部 ==="
tail -30 /tmp/eng_run.log 2>/dev/null
