#!/bin/bash
PW=MAO5201314sm
# 1) 本地 UDP 接收(1514)，后台写文件
pkill -f 'udp_sink' 2>/dev/null
cat > /tmp/udp_sink.py <<'PY'
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1',1514))
s.settimeout(20)
open('/tmp/syslog_rcv.txt','w').close()
try:
    while True:
        data,_=s.recvfrom(2048)
        with open('/tmp/syslog_rcv.txt','a') as f: f.write(data.decode('utf-8','replace')+'\n')
except Exception: pass
PY
nohup python3 /tmp/udp_sink.py >/dev/null 2>&1 &
sleep 1

# 2) 登录
TOK=$(curl -s -H "Content-Type: application/json" --data '{"username":"admin","password":"Admin@2026"}' http://127.0.0.1:18081/api/auth/login | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
echo "token=${TOK:0:16}..."

# 3) 配置 syslog 外发到本地 1514
curl -s -X PUT -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  --data '{"enabled":true,"host":"127.0.0.1","port":1514,"protocol":"udp","facility":"local0","tag":"novawaf","minLevel":"info","forwardAlerts":true,"forwardRuntime":true}' \
  http://127.0.0.1:18081/api/waf/syslog -o /dev/null -w "save_syslog=%{http_code}\n"

# 4) 触发攻击产生事件
curl -s -o /dev/null -w "sqli=%{http_code}\n" "http://127.0.0.1:8099/api/x?q=1%20UNION%20SELECT%20password%20FROM%20users" -H "Host: nac"
sleep 6

# 5) 发测试消息
curl -s -X POST -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" --data '{}' http://127.0.0.1:18081/api/waf/syslog/test; echo

# 6) 检查接收
sleep 3
echo "=== 收到的 syslog 报文 ==="
cat /tmp/syslog_rcv.txt 2>/dev/null | head -10
echo "行数: $(wc -l < /tmp/syslog_rcv.txt 2>/dev/null)"
pkill -f 'udp_sink' 2>/dev/null
echo "SYSLOG_TEST_DONE"
