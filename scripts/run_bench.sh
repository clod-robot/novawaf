#!/usr/bin/env bash
# 在服务器上运行两组压测
sudo -n sysctl -w net.ipv4.ip_local_port_range="1024 65535" net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1
echo "############### 正常流量 ###############"
python3 /tmp/bench.py '/index.html?q=hello'
echo ""
echo "############### 攻击流量(SQLi) ###############"
python3 /tmp/bench.py "/?id=1'%20or%20'1'='1"
