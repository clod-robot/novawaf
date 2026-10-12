#!/bin/bash
R=/usr/local/redis/bin/redis-cli
echo "=== novawaf:stats (前 1500 字符) ==="
$R GETRANGE novawaf:stats 0 1500
echo ""
echo "=== novawaf:logs 类型+长度 ==="
$R TYPE novawaf:logs; $R STRLEN novawaf:logs
echo "=== novawaf:logs 前 800 字符 ==="
$R GETRANGE novawaf:logs 0 800
echo ""
echo "=== novawaf:events 最新 2 条 ==="
$R LRANGE novawaf:events -2 -1
echo "=== traffic keys ==="
$R --scan --pattern "novawaf:traffic*"
