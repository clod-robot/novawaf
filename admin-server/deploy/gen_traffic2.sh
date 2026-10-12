#!/bin/bash
U[0]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
U[1]="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
U[2]="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
U[3]="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36 Edg/119.0"
U[4]="curl/8.0"
P=( "/" "/index.html" "/login" "/api/user?id=1" "/nonexistent" "/about" "/" "/index.html" )
for i in $(seq 1 40); do
  ua=${U[$((i % 5))]}; p=${P[$((i % 8))]}
  ref="https://$([ $((i % 3)) -eq 0 ] && echo google.com || [ $((i % 3)) -eq 1 ] && echo baidu.com || echo bing.com)/search?q=$i"
  curl -s -o /dev/null -H "Host: a.test" -A "$ua" -e "$ref" "http://127.0.0.1:8099$p" --max-time 2
done
sleep 2
/usr/local/redis/bin/redis-cli -h 127.0.0.1 LLEN novawaf:access
