#!/usr/bin/env python3
# 压测专用源站：在被测机本地 127.0.0.1:18092 应答，模拟被保护业务（HTTP/1.1 keep-alive，恒定 200）。
# 仅为本机回环压测服务，不监听外网。
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18092
BODY = b"ok"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.wfile.write(BODY)
        except Exception:
            pass

    def do_GET(self):
        self._reply()

    def do_POST(self):
        if self.headers.get("Content-Length"):
            try:
                self.rfile.read(int(self.headers["Content-Length"]))
            except Exception:
                pass
        self._reply()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    srv.daemon_threads = True
    print(f"bench origin on 127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()
