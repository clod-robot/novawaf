#!/bin/bash
H="Host: nac"
t() { printf "%-46s -> " "$1"; curl -s -o /dev/null -w "%{http_code}\n" --max-time 4 -H "$H" "http://127.0.0.1:8099$2"; }
echo "=== 误报应消除（放行，到上游后 401/200 均可，只要不是 403） ==="
t "system/info  (误报用例)"          "/api/auth/system/info"
t "public/info  (误报用例)"          "/api/auth/public/info"
echo "=== 真实攻击仍应拦截（403） ==="
t "SQLi UNION SELECT"               "/api/x?q=1%20UNION%20SELECT%20password%20FROM%20users"
t "真实 XXE payload"                "/api/x?b=%3C%21DOCTYPE+foo+%5B+%3C%21ENTITY+xxe+SYSTEM+%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E+%5D%3E"
t "XSS"                            "/api/x?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
t "路径遍历"                        "/api/x?f=..%2F..%2Fetc%2Fpasswd"
