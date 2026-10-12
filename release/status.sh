#!/usr/bin/env bash
PREFIX=/opt/novawaf
echo "进程:"
for s in engine admin; do
  f="$PREFIX/run/$s.pid"
  if [ -f "$f" ] && kill -0 "$(cat "$f")" 2>/dev/null; then echo "  $s: 运行中 pid=$(cat "$f")"; else echo "  $s: 未运行"; fi
done
echo "监听端口:"
for p in 8099 18081; do (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null) | grep -q ":$p " && echo "  :$p 监听中" || echo "  :$p 未监听"; done
