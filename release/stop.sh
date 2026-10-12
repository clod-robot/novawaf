#!/usr/bin/env bash
PREFIX=/opt/novawaf
for s in engine admin; do
  f="$PREFIX/run/$s.pid"
  if [ -f "$f" ]; then
    pid=$(cat "$f"); kill "$pid" 2>/dev/null && echo "已停止 $s (pid $pid)" || echo "$s 未运行"
    rm -f "$f"
  fi
done
pkill -x novawaf-engine 2>/dev/null && echo "已清理残留引擎进程" || true
