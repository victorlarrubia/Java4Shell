#!/usr/bin/env python3
# Mock server simulating VulnApp for OOB trigger smoke testing.
# Replicates the exact behavior of VulnApp.safeDecode():
#   - Valid Base64   → {"result":"<decoded_text>"}  HTTP 200
#   - Malformed B64  → {"result":"[decode error: Illegal base64 character =]"}  HTTP 200
# This is the exact response that our new soft-signal detection should catch.

import base64
import http.server
import json
import threading
import sys

PORT = 8080

class VulnHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass   # silence request log

    def _respond(self, code, body_dict):
        body = json.dumps(body_dict).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "VulnApp/1.0 (Java/25.0.4)")
        self.send_header("X-Powered-By", "Java/25.0.4 G1GC")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode(errors="replace") if length else ""

    def _safe_decode(self, b64_input):
        try:
            decoded = base64.b64decode(b64_input.strip(), validate=True)
            return decoded.decode("utf-8", errors="replace")
        except Exception as e:
            # Exactly what VulnApp.safeDecode() returns
            return f"[decode error: {e}]"

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "UP"})
        elif self.path == "/":
            self._respond(200, {"app": "Java4Shell Test Server", "cve": "CVE-2026-114938",
                                "java": "25.0.4",
                                "surfaces": ["/api/decode", "/saml/SSO", "/auth/", "/login"]})
        elif self.path.startswith("/auth/"):
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Basic "):
                b64 = auth[6:].strip()
                decoded = self._safe_decode(b64)
                self._respond(401, {"error": "Unauthorized", "decoded_len": len(decoded),
                                    "result": decoded[:200]})
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="VulnApp"')
                self.end_headers()
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self):
        body = self._read_body()

        if self.path == "/api/decode":
            # Naive JSON extract — same as VulnApp
            data = ""
            idx = body.find('"data"')
            if idx >= 0:
                q1 = body.find('"', idx + 7)
                q2 = body.find('"', q1 + 1) if q1 >= 0 else -1
                if q1 >= 0 and q2 > q1:
                    data = body[q1+1:q2]
            decoded = self._safe_decode(data)
            self._respond(200, {"result": decoded[:200]})

        elif self.path == "/saml/SSO":
            saml_req = ""
            for part in body.split("&"):
                if part.startswith("SAMLRequest="):
                    from urllib.parse import unquote
                    saml_req = unquote(part[12:])
            decoded = self._safe_decode(saml_req) if saml_req else ""
            self._respond(200, {"saml_decoded_len": len(decoded)})

        elif self.path == "/login":
            username = ""
            for part in body.split("&"):
                if part.startswith("username="):
                    from urllib.parse import unquote
                    username = unquote(part[9:])
            decoded = self._safe_decode(username) if username else ""
            self._respond(401, {"error": "Invalid credentials", "user_len": len(decoded)})

        elif self.path == "/upload":
            decoded = ""
            for line in body.splitlines():
                line = line.strip()
                if len(line) > 20 and all(c in
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in line):
                    decoded = self._safe_decode(line)
                    break
            self._respond(200, {"upload": "ok", "decoded_len": len(decoded)})

        else:
            self._respond(404, {"error": "not found"})


def start(port=PORT, daemon=True):
    server = http.server.HTTPServer(("127.0.0.1", port), VulnHandler)
    t = threading.Thread(target=server.serve_forever, daemon=daemon)
    t.start()
    return server


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    print(f"[mock-vulnapp] Listening on :{port}")
    s = start(port, daemon=False)
