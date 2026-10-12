#!/bin/bash
R=/usr/local/redis/bin/redis-cli
echo "=== keys *rule* ==="; $R --scan --pattern "*rule*"
echo "=== keys *app* ==="; $R --scan --pattern "*app*"
echo "=== novawaf:rules ==="; $R GET novawaf:rules
echo "=== novawaf:meta HGETALL ==="; $R HGETALL novawaf:meta
echo "=== ioc head ==="; $R GETRANGE novawaf:ioc 0 100
echo "=== ioc strlen ==="; $R STRLEN novawaf:ioc
