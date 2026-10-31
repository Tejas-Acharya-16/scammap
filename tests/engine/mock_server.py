"""Throwaway local server for testing app/static/index.html in a browser: the real engine behind the
API routes, a fake licence switch (POST /__toggle). Not the team's server; for UI checks only."""
import json
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from app.demo import run as demo_run  # noqa: E402
from app.engine import Engine, Registry  # noqa: E402

REGISTRY = Registry.from_dir(ROOT / "app" / "data")
ENGINE = Engine(REGISTRY, salt="mock-server-salt")
STATE = {"valid": True, "licensee": "Demo Bank", "expires_at": "2027-01-31T23:59:59+05:30"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _gate(self, path):
        if STATE["valid"] or path in ("/", "/judge", "/health", "/license", "/__toggle"):
            return False
        self._send(403, {"error": "LICENSE_EXPIRED"})
        return True

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        now = datetime.now(timezone.utc)
        if self._gate(u.path):
            return
        if u.path == "/":
            return self._send(200, (ROOT / "app" / "static" / "index.html").read_bytes(), "text/html; charset=utf-8")
        if u.path == "/judge":
            return self._send(200, (ROOT / "app" / "static" / "judge.html").read_bytes(), "text/html; charset=utf-8")
        if u.path == "/health":
            return self._send(200, {"ok": True})
        if u.path == "/license":
            left = (datetime.fromisoformat(STATE["expires_at"]) - now).total_seconds()
            return self._send(200, {"licensee": STATE["licensee"], "expires_at": STATE["expires_at"],
                                    "status": "valid" if STATE["valid"] else "expired", "valid": STATE["valid"],
                                    "seconds_remaining": max(0, int(left)) if STATE["valid"] else 0})
        if u.path == "/lookup":
            return self._send(*ENGINE.lookup(q.get("type"), q.get("value"), now))
        if u.path == "/map":
            return self._send(*ENGINE.map(q.get("pincode"), q.get("days"), q.get("radius_km"), now))
        if u.path == "/alerts":
            return self._send(*ENGINE.alerts(q.get("pincode"), now))
        if u.path in ("/reports", "/challenges", "/admin/reset", "/demo/run"):
            return self._send(405, {"error": "method_not_allowed"})
        self._send(404, {"error": "not_found"})

    def do_DELETE(self):
        u = urlsplit(self.path)
        if self._gate(u.path):
            return
        known = ("/health", "/lookup", "/map", "/alerts", "/reports", "/challenges", "/admin/reset", "/license", "/demo/run")
        self._send(405 if u.path in known else 404, {"error": "method_not_allowed" if u.path in known else "not_found"})

    def do_POST(self):
        u = urlsplit(self.path)
        if self._gate(u.path):
            return
        n = int(self.headers.get("content-length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"null")
        except ValueError:
            return self._send(400, {"error": "invalid_body"})
        now = datetime.now(timezone.utc)
        if u.path == "/__toggle":
            STATE["valid"] = not STATE["valid"]
            return self._send(200, STATE)
        if u.path == "/reports":
            return self._send(*ENGINE.handle_report(body, now, self.client_address[0]))
        if u.path == "/challenges":
            return self._send(*ENGINE.handle_challenge(body, now))
        if u.path == "/admin/reset":
            ENGINE.reset()
            return self._send(200, {"ok": True})
        if u.path == "/demo/run":
            return self._send(200, demo_run(REGISTRY, ENGINE.config, (body or {}).get("seed")))
        if u.path == "/license":            # MOCK ONLY: no signature check here; the real server verifies Ed25519
            if not isinstance(body, dict) or "expires_at" not in body:
                return self._send(400, {"error": "INVALID_LICENSE"})
            STATE.update(licensee=body.get("licensee", "?"), expires_at=body["expires_at"])
            STATE["valid"] = datetime.fromisoformat(body["expires_at"]) > now
            return self._send(200, {"ok": True, "status": "valid" if STATE["valid"] else "expired"})
        if u.path in ("/health", "/lookup", "/map", "/alerts"):
            return self._send(405, {"error": "method_not_allowed"})
        self._send(404, {"error": "not_found"})


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8765), H).serve_forever()
