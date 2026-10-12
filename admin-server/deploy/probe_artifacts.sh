#!/bin/bash
echo "=== 现有产物 ==="
ls -la /tmp/novawaf-engine 2>/dev/null && file /tmp/novawaf-engine 2>/dev/null | cut -d: -f2
ls -la /home/mao/novawaf/admin-server/target/*.jar 2>/dev/null
echo "--- 前端 dist ---"
ls -d /var/www/*/dist 2>/dev/null; ls /home/mao/novawaf/admin-web/dist 2>/dev/null | head
echo "--- 规则数据 ---"
ls /home/mao/novawaf/yara-rules/ 2>/dev/null
ls /home/mao/novawaf/engine/rules/ 2>/dev/null
echo "--- 工具链 ---"
which g++ make tar java 2>/dev/null
echo "--- redis ---"
which redis-server redis-cli 2>/dev/null; systemctl is-active redis 2>/dev/null
