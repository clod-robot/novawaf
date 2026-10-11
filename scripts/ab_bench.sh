#!/usr/bin/env bash
sudo -n sysctl -w net.ipv4.ip_local_port_range="1024 65535" net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1
for c in 50 100 200 400 800; do
  echo "=== 并发 $c ==="
  ab -n 40000 -c $c http://127.0.0.1:18080/index.html 2>&1 | \
    grep -E 'Requests per second|Failed requests' | tr '\n' ' '
  echo
done
echo "=== 压后存活 ==="
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/index.html
