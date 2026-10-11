#!/usr/bin/env python3
"""Mock LLM server (OpenAI-compatible /v1/chat/completions) for NovaWAF AI tests.
Returns a JSON verdict. Toggle behavior via path: /block -> attack, /pass -> benign."""
import http.server, json, sys, threading, urllib.parse

MODE = sys.argv[1] if len(sys.argv) > 1 else "pass"  # pass | block
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18090

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        if MODE == "slow":
            import time; time.sleep(3)  # 模拟超时
        verdict = {"block": MODE == "block", "category": "SQLi" if MODE=="block" else "Benign",
                   "confidence": 0.9, "reason": "mock"}
        body = json.dumps({"choices":[{"message":{"content":json.dumps(verdict)}}]})
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

print(f"mock LLM mode={MODE} on :{PORT}", flush=True)
http.server.HTTPServer(("127.0.0.1", PORT), H).serve_forever()
