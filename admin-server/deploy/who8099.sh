#!/bin/bash
SUDO() { printf '%s\n' 'MAO5201314sm' | sudo -S -p '' "$@"; }
echo "=== 谁占着 8099 ==="
SUDO ss -ltnp 2>/dev/null | grep ':8099'
echo "=== fuser ==="
SUDO fuser -n tcp 8099 2>&1
echo "=== 所有 novawaf/nc/python 监听 ==="
SUDO lsof -iTCP:8099 -sTCP:LISTEN 2>/dev/null
echo "=== pgrep engine ==="
pgrep -af novawaf-engine
