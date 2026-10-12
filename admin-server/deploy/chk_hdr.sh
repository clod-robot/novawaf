#!/bin/bash
echo "=== captcha 响应头（直连网关，看 Content-Length / Transfer-Encoding / Connection） ==="
curl -s -D - -o /dev/null --max-time 5 -H "Host: nac" http://127.0.0.1:8080/api/auth/captcha
echo "=== 经 WAF 的响应头 ==="
curl -s -D - -o /dev/null --max-time 6 -H "Host: nac" http://127.0.0.1:8099/api/auth/captcha
echo "=== 对比：info 401 响应头 ==="
curl -s -D - -o /dev/null --max-time 5 -H "Host: nac" http://127.0.0.1:8080/api/auth/info
