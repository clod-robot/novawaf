#!/bin/bash
python3 - <<'PY'
import socket
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try:
    s.bind(("0.0.0.0",8099)); s.listen(); print("BIND_OK")
except Exception as e:
    print("BIND_FAIL",e)
PY
ss -ltn 2>/dev/null | grep ':8099' && echo "PORT_IN_USE" || echo "PORT_FREE"
pgrep -a novawaf-engine
