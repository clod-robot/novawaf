#!/bin/bash
echo "=== MaxMind / mmdb 文件 ==="
find / -name '*.mmdb' 2>/dev/null | head; find /home/mao -iname '*geo*' 2>/dev/null | head
echo "=== maxmind 脚本 ==="
ls -la /home/mao/novawaf/scripts/maxmind_to_redis.py 2>/dev/null
echo "=== 后端读取 redis geoip(用 java 不方便, 看引擎加载日志) ==="
grep -i 'geoip\|GeoIP' /tmp/novawaf-engine.log 2>/dev/null | tail -3
grep -i 'geoip\|GeoIP' /tmp/*.log 2>/dev/null | tail -3
echo "=== python 是否有 geoip 库 ==="
python3 -c 'import maxminddb; print("maxminddb OK", maxminddb.__version__)' 2>&1 | head -1