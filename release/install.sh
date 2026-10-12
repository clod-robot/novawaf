#!/usr/bin/env bash
# NovaWAF 一键安装（幂等，可重复执行）。将运行包部署到 /opt/novawaf 并注册服务。
set -euo pipefail
PREFIX=/opt/novawaf
HERE="$(cd "$(dirname "$0")" && pwd)"
SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

echo "[1/5] 部署文件到 $PREFIX"
$SUDO mkdir -p "$PREFIX"/{bin,lib,web,rules/yara,run,logs}
$SUDO cp -f "$HERE/bin/novawaf-engine" "$PREFIX/bin/" && $SUDO chmod +x "$PREFIX/bin/novawaf-engine"
$SUDO cp -f "$HERE/bin/novawaf-admin.jar" "$PREFIX/bin/"
$SUDO cp -rf "$HERE/web/." "$PREFIX/web/" 2>/dev/null || true
$SUDO cp -rf "$HERE/rules/." "$PREFIX/rules/"
[ -f "$HERE/lib/libyara.so.10" ] && $SUDO cp -f "$HERE/lib/libyara.so.10" "$PREFIX/lib/"
$SUDO cp -f "$HERE/start.sh" "$HERE/stop.sh" "$HERE/status.sh" "$PREFIX/" && $SUDO chmod +x "$PREFIX"/*.sh
[ -f "$HERE/conf/application.yml" ] && $SUDO cp -f "$HERE/conf/application.yml" "$PREFIX/bin/"

echo "[2/5] 生成环境配置"
if [ ! -f "$PREFIX/novawaf.env" ]; then
  $SUDO cp "$HERE/env.example" "$PREFIX/novawaf.env"
  echo "    已生成 $PREFIX/novawaf.env，请按需修改端口/Redis 后再启动"
fi

echo "[3/5] 依赖检查：libyara"
if ! ldconfig -p 2>/dev/null | grep -q libyara; then
  if [ -f "$PREFIX/lib/libyara.so.10" ]; then
    echo "    使用捆绑的 libyara（启动脚本自动 LD_LIBRARY_PATH）"
  else
    echo "    警告：未检测到 libyara，请先安装 yara（apt install libyara10）或在包内提供 lib/libyara.so.10"
  fi
fi

echo "[4/5] 注册 systemd 服务"
if [ -f "$HERE/conf/novawaf-engine.service" ]; then
  $SUDO cp -f "$HERE/conf/novawaf-engine.service" /etc/systemd/system/novawaf-engine.service
  $SUDO systemctl daemon-reload
fi

echo "[5/5] 完成"
echo "  引擎: $PREFIX/bin/novawaf-engine  管理后端: $PREFIX/bin/novawaf-admin.jar  前端: $PREFIX/web"
echo "  启动: $PREFIX/start.sh   停止: $PREFIX/stop.sh   状态: $PREFIX/status.sh"
echo "  配置: $PREFIX/novawaf.env"
