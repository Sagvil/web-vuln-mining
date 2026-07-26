"""Minimal loopback-only HexStrike policy health and audit service."""
from __future__ import annotations
import argparse, json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
# ============================ Configuration zone ============================
MAX_BODY_BYTES = 256 * 1024  # Maximum accepted policy/audit request body.
# ============================================================================
class Handler(BaseHTTPRequestHandler):
    audit_log: Path
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self) -> None:
        self._send(200, {"status": "ok", "service": "hexstrike-policy", "timestamp": datetime.now(timezone.utc).isoformat()}) if self.path in {"/health", "/policy/health"} else self._send(404, {"status": "not-found"})
    def do_POST(self) -> None:
        if self.path != "/policy/audit": self._send(404, {"status": "not-found"}); return
        try: payload = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", "0")), MAX_BODY_BYTES)) or b"{}")
        except json.JSONDecodeError: self._send(400, {"status": "invalid-json"}); return
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_log.open("a", encoding="utf-8") as handle: handle.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "event": "policy-audit", "payload": payload}, ensure_ascii=False) + "\n")
        self._send(202, {"status": "recorded"})
    def log_message(self, *_: object) -> None: pass
def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--bind", default="127.0.0.1:8888"); parser.add_argument("--audit-log", type=Path, required=True); args = parser.parse_args()
    host, port = args.bind.rsplit(":", 1); Handler.audit_log = args.audit_log; ThreadingHTTPServer((host, int(port)), Handler).serve_forever(); return 0
if __name__ == "__main__": raise SystemExit(main())
