#!/bin/bash
# 构建 NovaWAF C++ 管理控制台（Drogon）。
# 前置：~/deps 下已安装 drogon + jsoncpp + uuid，~/cmake-3.30.5-linux-x86_64 有 cmake。
# 运行: bash scripts/build_console.sh
set -e
export PATH=$HOME/cmake-3.30.5-linux-x86_64/bin:$PATH
PREFIX=${DEPS_PREFIX:-$HOME/deps}
cd "$(dirname "$0")/../console"
cmake -B build -DCMAKE_PREFIX_PATH="$PREFIX"
cmake --build build -j"$(nproc)"
echo "built: console/build/novawaf-console"
