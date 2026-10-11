#!/usr/bin/env bash
# NovaWAF - Linux 一键构建脚本 (Ubuntu 20.04+/Debian)
# 用法: bash build.sh
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"

echo "[1/4] 安装编译依赖 (g++ cmake make)..."
if command -v apt-get >/dev/null; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq build-essential cmake make >/dev/null
fi

echo "[2/4] 编译 C++ 检测引擎..."
mkdir -p "$BUILD" && cd "$BUILD"
cmake "$ROOT/engine" -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)"

echo "[3/4] 编译 XDP/eBPF 过滤器 (可选)..."
if command -v clang >/dev/null; then
  (cd "$ROOT/xdp" && make) || echo "XDP 编译跳过（缺 clang/libbpf）"
else
  echo "XDP 编译跳过（未安装 clang）"
fi

echo "[4/4] 打包管理后台..."
if command -v mvn >/dev/null; then
  (cd "$ROOT/management" && mvn -q -DskipTests package)
fi

echo ""
echo "构建完成!"
echo "  引擎: $BUILD/novawaf-engine"
echo "  测试: $BUILD/test_core  (运行: ctest --output-on-failure)"
echo "  启动: $BUILD/novawaf-engine 8080 $(nproc)"
