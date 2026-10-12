#!/usr/bin/env bash
# 启动 NovaWAF（引擎 + 管理后端）。读取 /opt/novawaf/novawaf.env。
set -euo pipefail
PREFIX=/opt/novawaf
cd "$PREFIX"
[ -f "$PREFIX/novawaf.env" ] && set -a && . "$PREFIX/novawaf.env" && set +a

export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"
export NOVA_REDIS_HOST="${NOVA_REDIS_HOST:-127.0.0.1}"
export NOVA_YARA_RULES="${NOVA_YARA_RULES:-$PREFIX/rules/yara}"

mkdir -p "$PREFIX/run" "$PREFIX/logs"

echo "启动引擎 (port ${ENGINE_PORT:-8099})..."
nohup "$PREFIX/bin/novawaf-engine" "${ENGINE_PORT:-8099}" "${ENGINE_THREADS:-4}" \
  >"$PREFIX/logs/engine.log" 2>&1 &
echo $! > "$PREFIX/run/engine.pid"

echo "启动管理后端 (port ${ADMIN_PORT:-18081})..."
nohup java -jar "$PREFIX/bin/novawaf-admin.jar" --server.port="${ADMIN_PORT:-18081}" \
  >"$PREFIX/logs/admin.log" 2>&1 &
echo $! > "$PREFIX/run/admin.pid"

sleep 2
echo "引擎 pid=$(cat $PREFIX/run/engine.pid)  后端 pid=$(cat $PREFIX/run/admin.pid)"
"$PREFIX/status.sh"
