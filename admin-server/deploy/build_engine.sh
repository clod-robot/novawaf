#!/bin/bash
set -e
cd /home/mao/novawaf/engine
g++ -std=c++20 -O2 -Wall -pthread -I include src/main.cpp -o /tmp/novawaf-engine.new -lpthread 2>/tmp/gcc.log
echo "BUILD_DONE rc=$?"
if [ -s /tmp/gcc.log ]; then echo "--- warnings/errors ---"; cat /tmp/gcc.log; fi
ls -la /tmp/novawaf-engine.new
