#!/usr/bin/env python3
"""Read-only HTTP publisher for the generated reports; Python standard library only."""
import os, hmac, json, logging, threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote

from scan_control import CONTROL

log = logging.getLogger("supply-chain.http")

BIND = os.getenv("REPORT_HTTP_BIND", "0.0.0.0")
PORT = int(os.getenv("REPORT_HTTP_PORT", "8080"))
TOKEN = os.getenv("REPORT_TOKEN", "").strip()
ROOT = Path(os.getenv("REPORT_DIR", "/reports"))
COOKIE = "sbom_token"
HEALTH_PATH = "/healthz"
SCAN_PATH = "/api/scan"
SCAN_STATUS_PATHS = (SCAN_PATH, SCAN_PATH + "/status")
RETRY_AFTER = os.getenv("SCAN_RETRY_AFTER_SECONDS", "10")


class ReportHandler(SimpleHTTPRequestHandler):
    server_version = "verdaccio-supply-chain-report/1.0"
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def _cookie_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return unquote(value)
        return ""

    def _query_token(self, query):
        for value in parse_qs(query).get("token", []):
            if self._token_ok(value):
                return value
        return ""

    def _token_ok(self, value):
        if not TOKEN:
            return True
        return hmac.compare_digest(value.encode("utf-8"), TOKEN.encode("utf-8"))

    def _authorized(self, parsed):
        if not TOKEN:
            return True
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("bearer ") and self._token_ok(header[7:].strip()):
            return True
        if self._token_ok(self._cookie_token()):
            return True
        return bool(self._query_token(parsed.query))

    def _redirect_clean(self, path):
        self.send_response(302)
        self.send_header("Location", path)
        self.send_header("Set-Cookie", f"{COOKIE}={quote(TOKEN, safe='')}; HttpOnly; SameSite=Strict; Path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _unauthorized(self):
        self._json(401, {"error": "unauthorized",
                         "hint": "pass ?token=<REPORT_TOKEN> or Authorization: Bearer <REPORT_TOKEN>"})

    def _json(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _health(self):
        self._json(200, {"status": "ok", "report_dir": str(ROOT), "auth": "token" if TOKEN else "open"})

    def _scan_status(self):
        self._json(200, CONTROL.status())

    def _trigger_scan(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        accepted, detail = CONTROL.request()
        if not accepted:
            self._json(429, {"error": "scan_in_progress", "detail": detail, **CONTROL.status()},
                       {"Retry-After": RETRY_AFTER})
            return
        self._json(202, {"status": "accepted", "detail": detail, **CONTROL.status()})

    def _handle(self, body):
        parsed = urlparse(self.path)
        if parsed.path == HEALTH_PATH:
            self._health()
            return
        if not self._authorized(parsed):
            self._unauthorized()
            return
        if parsed.path in SCAN_STATUS_PATHS:
            self._scan_status()
            return
        if TOKEN and "token" in parse_qs(parsed.query):
            clean = dict(parse_qs(parsed.query))
            clean.pop("token", None)
            self._redirect_clean(parsed._replace(query=urlencode(clean, doseq=True)).geturl())
            return
        handle = self.send_head()
        if handle is None:
            return
        try:
            if body:
                self.copyfile(handle, self.wfile)
        finally:
            handle.close()

    def send_head(self):
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        if any(p.startswith(".") for p in parts):
            self.send_error(404, "Not Found")
            return None
        return super().send_head()

    def do_GET(self):
        self._handle(body=True)

    def do_HEAD(self):
        self._handle(body=False)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != SCAN_PATH:
            self._json(404, {"error": "not_found", "path": parsed.path})
            return
        if not self._authorized(parsed):
            self._unauthorized()
            return
        self._trigger_scan()


def start_server():
    ROOT.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((BIND, PORT), ReportHandler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, name="report-http", daemon=True)
    thread.start()
    log.info("Report server listening on http://%s:%s/ (dir=%s, auth=%s)",
             BIND, PORT, ROOT, "token" if TOKEN else "open")
    return httpd


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s")
    server = start_server()
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        server.shutdown()
