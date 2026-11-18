#!/usr/bin/env python3
"""Read-only HTTP publisher for the generated reports; Python standard library only."""
import os, hmac, json, logging, threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote

from scan_control import CONTROL, LOCK, REPORTS

log = logging.getLogger("supply-chain.http")
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

BIND = os.getenv("REPORT_HTTP_BIND", "0.0.0.0")
PORT = int(os.getenv("REPORT_HTTP_PORT", "8080"))
TOKEN = os.getenv("REPORT_TOKEN", "").strip()
ROOT = Path(os.getenv("REPORT_DIR", "/reports"))
COOKIE = "sbom_token"
HEALTH_PATH = "/healthz"
SCAN_PATH = "/api/scan"
SCAN_STATUS_PATHS = (SCAN_PATH, SCAN_PATH + "/status")
PROGRESS_PATH = "/progress"
PAGE_SIZE = max(20, int(os.getenv("REPORT_PAGE_SIZE", "100")))
RETRY_AFTER = os.getenv("SCAN_RETRY_AFTER_SECONDS", "10")

PROGRESS_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Scan progress</title><style>
*{box-sizing:border-box}body{margin:0;background:#f3f5f9;color:#172033;font:14px/1.5 system-ui,sans-serif}
header{background:#172b4d;color:#fff;padding:22px 20px}header h1{margin:0;font-size:21px}header p{color:#cbd6e8;margin:6px 0 0}
main{max-width:920px;margin:22px auto;padding:0 18px}
.card{background:#fff;border:1px solid #e3e8f0;border-radius:11px;padding:16px;margin-bottom:14px}
.bar{height:16px;background:#eef1f5;border-radius:20px;overflow:hidden;margin:8px 0 14px}
.bar>span{display:block;height:100%;width:0;background:linear-gradient(90deg,#315fbd,#5b8def);transition:width .4s}
table{border-collapse:collapse;width:100%}td,th{padding:7px 4px;border-bottom:1px solid #e5e9f0;text-align:left;vertical-align:top}
th{width:150px;color:#526078;font-weight:600}.mono{font-family:ui-monospace,monospace;font-size:12px}
button{padding:9px 16px;border:0;border-radius:8px;background:#315fbd;color:#fff;font-size:14px;cursor:pointer}
button:hover{background:#254a99}a{color:#315fbd}.hint{color:#68758b;font-size:13px}
</style></head><body><header><h1>Scan progress</h1><p id="state">loading…</p></header>
<main><section class="card"><div class="bar"><span id="fill"></span></div>
<table><tr><th>Current scan</th><td id="cur">-</td></tr>
<tr><th>Phase</th><td id="phase">-</td></tr>
<tr><th>Progress</th><td id="pct">-</td></tr>
<tr><th>Processed</th><td id="count" class="mono">-</td></tr>
<tr><th>Detail</th><td id="msg">-</td></tr>
<tr><th>Elapsed</th><td id="elapsed">-</td></tr>
<tr><th>Previous scan</th><td id="last">-</td></tr>
<tr><th>Updated</th><td id="updated" class="mono">-</td></tr></table></section>
<section class="card"><button id="go">Run scan now</button> <span class="hint" id="gomsg"></span>
<p><a id="report" href="/">Open latest report</a></p></section></main>
<script>
const $=id=>document.getElementById(id);
// resolve relative to the current page so a reverse proxy path prefix keeps working
const base=new URL('.',location.href).href;
const api=new URL('api/scan',base).href;
const token=new URLSearchParams(location.search).get('token');
const withToken=u=>token?u+(u.includes('?')?'&':'?')+'token='+encodeURIComponent(token):u;
$('report').href=base;
async function poll(){
 try{
  const d=await (await fetch(withToken(api),{headers:{Accept:'application/json'}})).json();
  const p=d.progress||{};
  $('state').textContent=(d.running?'SCAN RUNNING':'IDLE')+' · phase='+d.phase;
  $('phase').textContent=p.phase||'-';
  const known=(p.percent!==null&&p.percent!==undefined);
  $('fill').style.width=(known?p.percent:0)+'%';
  $('pct').textContent=known?p.percent+'%':'—';
  $('count').textContent=(p.current||0)+(p.total?' / '+p.total:'');
  $('msg').textContent=p.message||'-';
  $('elapsed').textContent=(d.elapsed_seconds===null||d.elapsed_seconds===undefined)?'-':d.elapsed_seconds+' s';
  $('updated').textContent=p.updated_at||'-';
  const s=d.last_summary;
  $('last').textContent=s?('packages '+s.unique_packages+' · versions '+s.package_versions+
    ' · findings '+s.vulnerability_findings+' · '+(s.duration_seconds||0)+'s'):'—';
  $('cur').textContent=d.running?('running · '+(p.phase||'-')+' '+(p.percent===null||p.percent===undefined?'':p.percent+'%')):'idle';
 }catch(e){$('state').textContent='error: '+e}
}
$('go').addEventListener('click',async()=>{
 try{
  const r=await fetch(withToken(api),{method:'POST'});
  if(r.status===202){$('gomsg').textContent='scan scheduled';}
  else if(r.status===429){$('gomsg').textContent='a scan is already running';}
  else{const b=(await r.text()).slice(0,160);$('gomsg').textContent='failed: HTTP '+r.status+' '+(b||'');}
 }catch(e){$('gomsg').textContent='failed: '+e}
 poll();
});
poll();setInterval(poll,2000);
</script></body></html>"""


PORTAL_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verdaccio Supply Chain Security</title><style>
*{box-sizing:border-box}body{margin:0;background:#f3f5f9;color:#172033;font:14px/1.5 system-ui,sans-serif}
header{background:#172b4d;color:white;padding:25px max(20px,calc((100vw - 1450px)/2))}header h1{margin:0;font-size:24px}header p{color:#cbd6e8;margin:5px 0}
main{max-width:1450px;margin:22px auto;padding:0 18px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}
.card,.panel{background:white;border:1px solid #e3e8f0;border-radius:11px;padding:15px}.card small{display:block;color:#68758b}.card strong{display:block;font-size:26px;margin-top:4px}
.panel{margin-top:16px}.toolbar{display:flex;gap:10px;margin:12px 0;flex-wrap:wrap;align-items:center}
input,select{padding:10px;border:1px solid #ccd4e2;border-radius:8px}input{flex:1;min-width:220px}
button{padding:9px 14px;border:1px solid #ccd4e2;border-radius:8px;background:#fff;cursor:pointer}button:hover{background:#eef2f9}
.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:1100px}td,th{padding:10px;border-bottom:1px solid #e5e9f0;text-align:left;vertical-align:top}th{background:#f8f9fc;color:#526078}
code{font-size:11px;overflow-wrap:anywhere}a{color:#315fbd}.risk{padding:2px 8px;border-radius:20px;background:#eef1f5;font-size:11px;font-weight:bold}
.critical,.high{background:#ffe3e3;color:#a51d2d}.medium{background:#fff0d4;color:#8a5700}.low{background:#e3f4e8;color:#176b37}
.notice{background:#fff8e8;padding:10px;border:1px solid #f0dfb4;border-radius:8px}.meta{color:#68758b;font-size:12px;margin-top:12px}
.pending{color:#8a5700;font-size:11px;font-weight:bold}
</style></head><body><header><h1>Verdaccio Supply Chain Security</h1><p>{{subtitle}}</p></header>
<main><section class="cards">{{cards}}</section>
<section class="panel"><h2>Package inventory</h2><form class="toolbar" method="get" action="/">
<input name="q" value="{{q}}" placeholder="Search package, version, hash, CVE…"><select name="risk">{{risks}}</select>
<button type="submit">Search</button><span class="meta">{{count}}</span></form>
<div class="tablewrap"><table id="tbl"><thead><tr><th>Package</th><th>Version</th><th>Risk</th><th>License</th><th>Tarball</th><th>SHA256</th><th>Dependencies</th><th>Vulnerabilities</th></tr></thead><tbody>{{rows}}</tbody></table></div>
{{pager}}
<div class="meta">JSON schema: {{schema}} · <a href="/latest.json">latest.json</a> · <a href="/progress">scan progress</a></div>{{notice}}</section></main></body></html>"""


def esc(value):
    import html as _html
    return _html.escape(str(value if value is not None else ""), quote=True)


def render_portal(report, query):
    """Server side pagination and search, the browser only receives one page."""
    packages = report.get("packages", [])
    summary = report.get("summary", {})
    pending = report.get("scan_state") == "pending"
    q = (query.get("q") or [""])[0].strip().lower()
    risk = (query.get("risk") or [""])[0].strip()
    try:
        page = max(1, int((query.get("page") or ["1"])[0]))
    except ValueError:
        page = 1

    def level_of(r):
        vulns = r.get("vulnerabilities", [])
        return max((v.get("severity", "UNKNOWN") for v in vulns), key=lambda x: RANK.get(x, 0),
                   default="PENDING" if pending else "NONE")

    def matches_row(r):
        if risk and level_of(r) != risk:
            return False
        if not q:
            return True
        haystack = (str(r.get("name", "")) + " " + str(r.get("version", "")) + " " + str(r.get("sha256", "")) +
                    " " + str(r.get("tarball_file", "")) + " " + str(r.get("license", "")) + " " +
                    " ".join(str(v.get("id", "")) for v in r.get("vulnerabilities", []))).lower()
        return q in haystack

    hits = [r for r in packages if matches_row(r)]
    pages = max(1, (len(hits) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, pages)
    chunk = hits[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]

    rows = []
    for r in chunk:
        vulns = r.get("vulnerabilities", [])
        level = level_of(r)
        vuln_html = "<br>".join(
            f'<a target="_blank" rel="noopener" href="{esc((v.get("references") or ["https://osv.dev/vulnerability/" + v["id"]])[0])}">{esc(v["id"])}</a> ({esc(v["severity"])})'
            for v in vulns) or ('<span class="pending">PENDING</span>' if pending else "—")
        dep = ", ".join(str(r.get("dependencies", "")).split(",")[:5])
        rows.append("<tr>" + "".join([
            f"<td>{esc(r.get('name'))}</td><td>{esc(r.get('version'))}</td>",
            f'<td><span class="risk {level.lower()}">{level}</span></td>',
            f"<td>{esc(r.get('license', 'UNKNOWN'))}</td><td>{esc(r.get('tarball_file', 'not found'))}</td>",
            f"<td><code>{esc(r.get('sha256', 'not calculated'))}</code></td><td>{esc(dep)}</td><td>{vuln_html}</td>"
        ]) + "</tr>")
    body = "\n".join(rows) or '<tr><td colspan="8">No matching package versions.</td></tr>'

    cards = [("Unique packages", summary.get("unique_packages", 0)), ("Package versions", summary.get("package_versions", 0)),
             ("Tarballs hashed", summary.get("tarballs_scanned", 0)),
             ("Vulnerable versions", "—" if pending else summary.get("versions_with_vulnerabilities", 0)),
             ("Vulnerability findings", "—" if pending else summary.get("vulnerability_findings", 0)),
             ("Dependency edges", summary.get("dependency_edges", 0))]
    card_html = "".join(f'<div class="card"><small>{esc(k)}</small><strong>{esc(v)}</strong></div>' for k, v in cards)
    risks = "".join(f'<option value="{esc(v)}"{" selected" if v == risk else ""}>{esc(v or "All severity")}</option>'
                    for v in ("", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "PENDING"))

    def link(target):
        return "/?" + "&amp;".join([f"q={quote(q)}", f"risk={quote(risk)}", f"page={target}"])

    pager = ""
    if pages > 1:
        prev = f'<a href="{link(max(1, page - 1))}">&larr; Prev</a>' if page > 1 else "&larr; Prev"
        nxt = f'<a href="{link(min(pages, page + 1))}">Next &rarr;</a>' if page < pages else "Next &rarr;"
        pager = (f'<div class="toolbar"><span class="meta">Page {page} / {pages} &middot; {len(hits)} matches</span>'
                 f"{prev} &nbsp; {nxt}</div>")
    notice = ""
    if pending:
        notice = '<p class="notice">Scan in progress &middot; vulnerability lookup is still pending</p>'
    elif report.get("osv", {}).get("error"):
        notice = f'<p class="notice">OSV query warning: {esc(report["osv"]["error"])}</p>'
    subtitle = (f'Full registry scan · {esc(report.get("generated_at", ""))} · '
                f'OSV {"enabled" if report.get("osv", {}).get("enabled") else "disabled"}')
    page = PORTAL_HEAD
    for key, value in {
            "subtitle": subtitle, "cards": card_html, "q": esc(q), "risks": risks,
            "count": f"{len(hits)} matching of {len(packages)} package versions",
            "rows": body, "pager": pager, "schema": esc(report.get("schema", "")), "notice": notice}.items():
        page = page.replace("{{" + key + "}}", value)
    return page


def matches(path, candidate):
    """Match a route by suffix so a reverse proxy path prefix keeps working."""
    return path == candidate or path.endswith(candidate)


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

    def _portal(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _scan_status(self):
        self._json(200, CONTROL.status())

    def _progress_page(self):
        body = PROGRESS_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _trigger_scan(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if LOCK.held_by_other():
            self._json(429, {"error": "another_scanner_active",
                             "detail": "another scanner is working on this report directory",
                             **CONTROL.status()}, {"Retry-After": RETRY_AFTER})
            return
        accepted, detail = CONTROL.request()
        if not accepted:
            self._json(429, {"error": "scan_in_progress", "detail": detail, **CONTROL.status()},
                       {"Retry-After": RETRY_AFTER})
            return
        self._json(202, {"status": "accepted", "detail": detail, **CONTROL.status()})

    def _handle(self, body):
        parsed = urlparse(self.path)
        if matches(parsed.path, HEALTH_PATH):
            self._health()
            return
        if not self._authorized(parsed):
            self._unauthorized()
            return
        if any(matches(parsed.path, p) for p in SCAN_STATUS_PATHS):
            self._scan_status()
            return
        if TOKEN and "token" in parse_qs(parsed.query):
            clean = dict(parse_qs(parsed.query))
            clean.pop("token", None)
            self._redirect_clean(parsed._replace(query=urlencode(clean, doseq=True)).geturl())
            return
        if matches(parsed.path, PROGRESS_PATH):
            self._progress_page()
            return
        if parsed.path in ("/", "/index.html"):
            report = REPORTS.get()
            if report is not None:
                self._portal(render_portal(report, parse_qs(parsed.query)))
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

    def translate_path(self, path):
        """Serve report files when a reverse proxy keeps its path prefix."""
        translated = super().translate_path(path)
        if os.path.exists(translated):
            return translated
        clean = path.split("?", 1)[0].split("#", 1)[0]
        words = [w for w in clean.split("/") if w]
        trailing = clean.endswith("/")
        for i in range(1, len(words) + 1):
            suffix = "/" + "/".join(words[i:])
            if trailing and not suffix.endswith("/"):
                suffix += "/"
            candidate = super().translate_path(suffix)
            if os.path.exists(candidate):
                return candidate
        return translated

    def do_GET(self):
        self._handle(body=True)

    def do_HEAD(self):
        self._handle(body=False)

    def do_POST(self):
        parsed = urlparse(self.path)
        if not matches(parsed.path, SCAN_PATH):
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
                        format="{{asctime}} {{levelname}} {{message}}")
    server = start_server()
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        server.shutdown()
