#!/bin/bash
PW=MAO5201314sm
echo "[后端状态]"
sleep 30
ps -ef | grep '[n]ovawaf-admin.jar' | head -1 && echo "  后端进程存活" || echo "  后端未运行"
echo "[后端端口]"
(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ':18081' && echo "  18081 监听" || echo "  18081 未监听"
echo "[后端启动日志尾部]"
tail -5 /tmp/novawaf-admin.log 2>/dev/null

echo "[前端部署]"
rm -rf /tmp/distnew && mkdir -p /tmp/distnew
tar xzf /tmp/admin-web.tar.gz -C /tmp/distnew
echo "  解压后: $(ls /tmp/distnew | head -3)"
echo "$PW" | sudo -S -p '' bash -c 'rm -rf /var/www/novawaf-admin/* && cp -r /tmp/distnew/. /var/www/novawaf-admin/ && chown -R nginx:nginx /var/www/novawaf-admin' 2>&1 | tail -2
echo "  站点文件数: $(ls /var/www/novawaf-admin | wc -l)"

echo "[nginx SSE 配置]"
echo "$PW" | sudo -S -p '' cp /tmp/novawaf-admin.conf /etc/nginx/conf.d/novawaf-admin.conf 2>&1
echo "$PW" | sudo -S -p '' nginx -t 2>&1 | tail -2
for pid in $(ps -ef | grep '[n]ginx: master' | awk '{print $2}'); do
  echo "$PW" | sudo -S -p '' kill -HUP "$pid" 2>/dev/null && echo "  HUP master $pid"
done
echo "ALL_DONE"
