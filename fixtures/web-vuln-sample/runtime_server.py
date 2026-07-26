"""Small local Web/API fixture used to validate the workbench profiles."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Configuration zone: local-only listener for workbench acceptance tests.
LISTEN_HOST = "127.0.0.1"  # Loopback keeps the fixture confined to this workstation.
LISTEN_PORT = 18080  # Referenced by scopes/web-vuln-sample-runtime.yaml.


class FixtureHandler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: str, content_type: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - HTTP handler API requires this name.
        request = urlparse(self.path)
        if request.path == "/":
            self._send(200, "<html><body><a href='/search?q=hello'>search</a><script src='/frontend.js'></script></body></html>", "text/html; charset=utf-8")
        elif request.path == "/frontend.js":
            self._send(200, "fetch('/api/users?id=1');", "application/javascript; charset=utf-8")
        elif request.path == "/search":
            value = parse_qs(request.query).get("q", [""])[0]
            self._send(200, f"<html><body>search: {value}</body></html>", "text/html; charset=utf-8")
        elif request.path == "/api/users":
            self._send(200, json.dumps({"id": parse_qs(request.query).get("id", ["1"])[0], "name": "fixture"}), "application/json")
        elif request.path == "/openapi.json":
            schema = {"openapi": "3.0.3", "info": {"title": "Local fixture API", "version": "1.0"}, "servers": [{"url": f"http://{LISTEN_HOST}:{LISTEN_PORT}"}], "paths": {"/api/users": {"get": {"parameters": [{"name": "id", "in": "query", "schema": {"type": "integer"}}], "responses": {"200": {"description": "OK"}}}}}}
            self._send(200, json.dumps(schema), "application/json")
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), FixtureHandler).serve_forever()
