#!/usr/bin/env bash
# 双客户端并行判定：总RPS翻倍=客户端瓶颈；不变=服务器瓶颈
sudo -n sysctl -w net.ipv4.ip_local_port_range="1024 65535" net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1
python3 /tmp/bench.py '/index.html?q=hello' > /tmp/b1.txt 2>&1 &
P1=$!
python3 /tmp/bench.py '/index.html?q=hello' > /tmp/b2.txt 2>&1 &
P2=$!
wait $P1 $P2
echo "=== 客户端1 ==="; grep '并发 200' /tmp/b1.txt
echo "=== 客户端2 ==="; grep '并发 200' /tmp/b2.txt
R1=$(grep '并发 200' /tmp/b1.txt | grep -oP 'RPS\s+\K[0-9]+')
R2=$(grep '并发 200' /tmp/b2.txt | grep -oP 'RPS\s+\K[0-9]+')
echo "并发200单客户端≈3600；双客户端总和 = $((R1+R2))"
