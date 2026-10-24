"""Local web UI server. Stdlib only.

Threat model: other programs and web pages on this machine. Defences:
- binds 127.0.0.1 only;
- Host header allow-list (blocks DNS rebinding);
- per-run random token required on every API call, sent in a custom header
  (cross-site pages cannot set it without a CORS preflight we never answer);
- the browser is launched with a single-use code, not the token: browser argv
  is world-readable through `ps` on Linux, and a consumed code is worthless;
- strict CSP and no third-party resources.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .scan import HISTORY, run_scan

WEB = Path(__file__).parent / "web"
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}
# Routes come from the files shipped with the package, so no request data ever reaches a filesystem path.
STATIC |= {f"/i18n/{p.name}": (f"i18n/{p.name}", "application/json") for p in (WEB / "i18n").glob("*.json")}
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
        "require-trusted-types-for 'script'; trusted-types 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
MAX_BODY = 1024


class App(ThreadingHTTPServer):
    daemon_threads = True
    # On Windows SO_REUSEADDR lets another process bind the same 127.0.0.1:port and serve its own
    # page on our origin, which could read the token from location.hash. Claim the port exclusively.
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, port: int = 0, history: Path | None = HISTORY):
        super().__init__(("127.0.0.1", port), Handler)
        self.history = history
        self.token = secrets.token_urlsafe(32)
        self.launch_code: str | None = secrets.token_urlsafe(32)
        self.lock = threading.Lock()  # guards launch_code
        self.scan_lock = threading.Lock()
        self.allowed_hosts = {f"127.0.0.1:{self.server_port}", f"localhost:{self.server_port}"}

    # Secrets travel in the URL fragment: never sent in requests, never in logs or Referer.
    @property
    def url(self) -> str:
        """For the terminal only (the user's eyes): carries the token itself."""
        return f"http://127.0.0.1:{self.server_port}/#t={self.token}"

    @property
    def launch_url(self) -> str:
        """For the browser command line: carries a code that works once."""
        return f"http://127.0.0.1:{self.server_port}/#c={self.launch_code}"

    def redeem(self, code: object) -> str | None:
        with self.lock:
            if not (isinstance(code, str) and self.launch_code and hmac.compare_digest(code, self.launch_code)):
                return None
            self.launch_code = None
            return self.token


class Handler(BaseHTTPRequestHandler):
    server: App
    timeout = 10  # per socket operation: a local slowloris cannot pin threads forever
    server_version = "PortScope"
    sys_version = ""

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _host_ok(self) -> bool:
        if self.headers.get("Host") in self.server.allowed_hosts:
            return True
        self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "bad host"})
        return False

    def _authorized(self) -> bool:
        token = self.headers.get("X-PortScope-Token", "")
        if hmac.compare_digest(token.encode(), self.server.token.encode()):
            return True
        self._json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid token"})
        return False

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return
        path = self.path.split("?", 1)[0]
        if path not in STATIC:
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        name, ctype = STATIC[path]
        self._send(HTTPStatus.OK, (WEB / name).read_bytes(), ctype)

    def _body(self) -> dict | None:
        length = self.headers.get("Content-Length") or "0"
        if not length.isdigit() or int(length) > MAX_BODY:
            self._json(HTTPStatus.BAD_REQUEST, {"error": f"Content-Length must be 0..{MAX_BODY}"})
            return None
        try:
            body = json.loads(self.rfile.read(int(length)) or b"{}")
        except ValueError:
            body = None
        if not isinstance(body, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
            return None
        return body

    def do_POST(self):  # noqa: N802
        if not self._host_ok():
            return
        if self.path == "/api/session":
            body = self._body()
            if body is None:
                return
            token = self.server.redeem(body.get("code"))
            if token:
                return self._json(HTTPStatus.OK, {"token": token})
            return self._json(HTTPStatus.UNAUTHORIZED, {"error": "launch code invalid or already used"})
        if not self._authorized():
            return
        body = self._body()
        if body is None:
            return
        match self.path:
            case "/api/scan":
                self._scan(body.get("upnp", True) is not False)
            case "/api/quit":
                self._json(HTTPStatus.OK, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            case _:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def _scan(self, with_upnp: bool) -> None:
        if not self.server.scan_lock.acquire(blocking=False):
            self._json(HTTPStatus.CONFLICT, {"error": "scan already running"})
            return
        try:
            self._json(HTTPStatus.OK, run_scan(with_upnp, self.server.history))
        except NotImplementedError as e:
            self._json(HTTPStatus.NOT_IMPLEMENTED, {"error": str(e)})
        except Exception as e:  # surface to the UI instead of a dropped connection
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(e).__name__}: {e}"})
        finally:
            self.server.scan_lock.release()

    do_HEAD = do_GET
