#!/usr/bin/env bash
# NovaWAF - 部署到 Ubuntu 服务器 (本机执行，需能 SSH 到目标)
# 用法: bash deploy.sh <user@host> [port]
#   例: bash deploy.sh mao@192.168.100.2
set -e

TARGET="${1:?用法: bash deploy.sh user@host}"
REMOTE_DIR="/opt/novawaf"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo ">> 打包源码..."
cd "$ROOT"
tar czf /tmp/novawaf-src.tar.gz --exclude=build --exclude=target \
  engine xdp gateway management rules deploy scripts README.md .gitignore

echo ">> 上传到 $TARGET ..."
scp /tmp/novawaf-src.tar.gz "$TARGET:/tmp/"

echo ">> 在远端解压并构建..."
ssh "$TARGET" "
  set -e
  sudo rm -rf $REMOTE_DIR && sudo mkdir -p $REMOTE_DIR
  sudo tar xzf /tmp/novawaf-src.tar.gz -C $REMOTE_DIR
  sudo chown -R \$USER:\$USER $REMOTE_DIR
  cd $REMOTE_DIR
  bash scripts/build.sh
  echo '>> 安装 systemd 服务'
  sudo cp deploy/systemd/novawaf-engine.service /etc/systemd/system/
  sudo sed -i 's|/opt/novawaf/novawaf-engine|$REMOTE_DIR/build/novawaf-engine|' /etc/systemd/system/novawaf-engine.service
  sudo systemctl daemon-reload
  sudo systemctl enable --now novawaf-engine
  sleep 1
  sudo systemctl status novawaf-engine --no-pager | head -5
  echo '>> 部署完成，引擎监听 8080'
"
echo ">> 完成"
