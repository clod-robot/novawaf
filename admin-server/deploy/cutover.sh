#!/bin/bash
set -e
SUDO() { printf '%s\n' 'MAO5201314sm' | sudo -S -p '' "$@"; }
CONF=/etc/nginx/conf.d/nac.conf
TS=$(date +%Y%m%d_%H%M%S)
BAK=/etc/nginx/conf.d/nac.conf.bak_$TS

echo "=== 1) 备份原配置 -> $BAK ==="
SUDO cp $CONF $BAK
echo "backup: $BAK"

echo "=== 2) 安装新配置(WAF 前置) ==="
SUDO cp /tmp/nac.conf.new $CONF

echo "=== 3) nginx -t 语法校验 ==="
if ! SUDO nginx -t 2>&1; then
  echo "!!! 配置校验失败，自动回滚 !!!"
  SUDO cp $BAK $CONF
  SUDO nginx -s reload
  echo "已回滚到 $BAK"
  exit 1
fi

echo "=== 4) reload nginx ==="
SUDO nginx -s reload
sleep 1
echo "reloaded"

echo "=== 5) 在线验证(经 HTTPS→WAF→gateway) ==="
echo -n "正常请求 /api/ 透传: "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/" --max-time 5
echo -n "SQLi 攻击拦截(期望403): "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/test?id=1'%20OR%20'1'='1" --max-time 5
echo -n "XSS 攻击拦截(期望403):  "; curl -sk -o /dev/null -w "%{http_code}\n" "https://127.0.0.1/api/x?q=<script>alert(1)</script>" --max-time 5

echo
echo "=== 回滚命令(如需): ==="
echo "sudo cp $BAK $CONF && sudo nginx -s reload"
echo "CUTOVER_DONE"
