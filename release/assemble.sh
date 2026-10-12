#!/usr/bin/env bash
# CI/本地通用：把 out/ 下已构建产物组装成自包含运行包。
# 约定输入: out/bin/novawaf-engine, out/bin/novawaf-admin.jar, out/web/(前端dist)
# 约定输出: out/novawaf-release.tar.gz
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/out}"
REL="$OUT/pkg/novawaf-release"
rm -rf "$OUT/pkg"; mkdir -p "$REL"/{bin,lib,web,conf,rules/yara}

echo "[assemble] 二进制 + jar"
cp -f "$OUT/bin/novawaf-engine" "$REL/bin/" && chmod +x "$REL/bin/novawaf-engine"
cp -f "$OUT/bin/novawaf-admin.jar" "$REL/bin/"

echo "[assemble] 捆绑 libyara（从引擎动态依赖解析）"
YL=$(ldd "$REL/bin/novawaf-engine" 2>/dev/null | grep -oE '/[^ ]*libyara[^ ]*' | head -1 || true)
[ -n "$YL" ] && cp -f "$YL" "$REL/lib/" && echo "  bundled $YL"

echo "[assemble] 前端"
[ -d "$OUT/web" ] && cp -rf "$OUT/web/." "$REL/web/"

echo "[assemble] 规则数据"
cp -f "$ROOT/yara-rules/base.yar" "$REL/rules/yara/" 2>/dev/null || true
cp -f "$ROOT/engine/rules/geoip.txt" "$REL/rules/" 2>/dev/null || true
cp -f "$ROOT/engine/rules/ioc.txt" "$REL/rules/" 2>/dev/null || true
printf '{"version":1,"rules":[]}\n' > "$REL/rules/default_rules.json"

echo "[assemble] 配置 + 脚本 + 文档"
cp -f "$ROOT/release/novawaf-engine.service" "$REL/conf/"
[ -f "$ROOT/admin-server/src/main/resources/application.yml" ] && cp -f "$ROOT/admin-server/src/main/resources/application.yml" "$REL/conf/"
[ -f "$ROOT/admin-server/deploy/nac.conf" ] && cp -f "$ROOT/admin-server/deploy/nac.conf" "$REL/conf/"
cp -f "$ROOT/release/"{install.sh,start.sh,stop.sh,status.sh,env.example,README-部署.md} "$REL/"
chmod +x "$REL"/*.sh

echo "[assemble] 打包"
tar czf "$OUT/novawaf-release.tar.gz" -C "$OUT/pkg" novawaf-release
ls -lh "$OUT/novawaf-release.tar.gz"
echo "ASSET=$OUT/novawaf-release.tar.gz"
