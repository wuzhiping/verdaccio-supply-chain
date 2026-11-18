#!/usr/bin/env python3
"""ntfy risk alerts for critical/high findings; Python standard library only."""
import os, json, time, hashlib, logging, urllib.request, urllib.error
from pathlib import Path
from urllib.parse import urlparse, quote

log = logging.getLogger("supply-chain.ntfy")

ENABLED = os.getenv("NTFY_ENABLED", "true").lower() not in ("0", "false", "no")
BASE_URL = os.getenv("NTFY_URL", "https://msn.feg.cn").strip().rstrip("/")
TOPIC = os.getenv("NTFY_TOPIC", "pub_abc").strip().strip("/")
MODE = os.getenv("NTFY_ALERT_MODE", "always").strip().lower()
TIMEOUT = max(3, int(os.getenv("NTFY_TIMEOUT_SECONDS", "10")))
RETRIES = max(0, int(os.getenv("NTFY_RETRIES", "2")))
MAX_BYTES = max(256, int(os.getenv("NTFY_MAX_MESSAGE_BYTES", "3500")))
MAX_ITEMS = max(1, int(os.getenv("NTFY_MAX_ITEMS", "20")))
PUBLIC_URL = os.getenv("REPORT_PUBLIC_URL", "").strip().rstrip("/")
STATE_FILE = Path(os.getenv("REPORT_DIR", "/reports")) / ".ntfy-state.json"
ALERT_LEVELS = ("CRITICAL", "HIGH")
SCOPE = os.getenv("NTFY_SCOPE", "relevant").strip().lower()


def endpoint():
    """Publish URL: NTFY_URL may already contain the topic, otherwise it is appended."""
    if not TOPIC:
        return BASE_URL
    last = urlparse(BASE_URL).path.rstrip("/").rsplit("/", 1)[-1]
    return BASE_URL if last == TOPIC else f"{BASE_URL}/{quote(TOPIC, safe='')}"


def relevant(pkg):
    """A version that matters for this registry: cached locally or the newest one."""
    return bool(pkg.get("tarball_file")) or bool(pkg.get("is_latest"))


def collect(report, scoped=True):
    """Collect the critical and high advisories, tagged with the registry relevance."""
    findings = []
    for pkg in report.get("packages", []):
        is_relevant = relevant(pkg)
        for vuln in pkg.get("vulnerabilities", []):
            level = (vuln.get("severity") or "UNKNOWN").upper()
            if level in ALERT_LEVELS:
                findings.append((level, str(pkg.get("name", "")), str(pkg.get("version", "")),
                                 str(vuln.get("id", "UNKNOWN")), is_relevant))
    findings.sort(key=lambda f: (0 if f[0] == "CRITICAL" else 1, f[1].lower(), f[2], f[3]))
    return findings


def truncate(text, limit):
    raw = text.encode("utf-8")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", "ignore") + "\n... (truncated)"


def signature(findings):
    joined = "\n".join(f"{f[0]}:{f[1]}@{f[2]}:{f[3]}" for f in findings)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def read_state():
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_state(sig):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({"signature": sig, "sent_at": time.time()}), encoding="utf-8")
    except OSError as e:
        log.debug("Cannot persist ntfy state: %s", e)


def unresolved(report, scoped=True):
    """Advisories whose severity could not be determined."""
    out = []
    for pkg in report.get("packages", []):
        if scoped and not relevant(pkg):
            continue
        for v in pkg.get("vulnerabilities", []):
            if (v.get("severity") or "UNKNOWN") == "UNKNOWN":
                out.append(v)
    return out


def build(report, findings, hidden=0):
    summary = report.get("summary", {})
    critical = sum(1 for f in findings if f[0] == "CRITICAL")
    high = sum(1 for f in findings if f[0] == "HIGH")
    osv_error = (report.get("osv") or {}).get("error")
    lines = ["Verdaccio SBOM risk alert",
             f"Scan time: {report.get('generated_at', 'unknown')}",
             f"Findings in scope: CRITICAL={critical} HIGH={high} ({len(findings)} advisories)",
             f"Vulnerable versions in scope: {len({(f[1], f[2]) for f in findings})}"]
    if osv_error:
        lines.append(f"WARNING: OSV query failed, results may be incomplete: {osv_error}")
    for level in ALERT_LEVELS:
        rows = [f for f in findings if f[0] == level]
        if not rows:
            continue
        lines.append("")
        lines.append(f"{level} ({len(rows)})")
        for _, name, version, vid, _rel in rows[:MAX_ITEMS]:
            lines.append(f"- {name}@{version} {vid}")
        if len(rows) > MAX_ITEMS:
            lines.append(f"- ... {len(rows) - MAX_ITEMS} more")
    if hidden:
        lines.append(f"{hidden} further advisories exist in historical versions that are not installed from this registry.")
    if PUBLIC_URL:
        lines.append("")
        lines.append(f"Report: {PUBLIC_URL}/")
    title = f"SBOM risk alert CRITICAL={critical} HIGH={high}"
    tags = []
    if critical:
        tags.append("rotating_light")
    if high:
        tags.append("warning")
    if not tags:
        tags.append("warning")
    priority = 5 if critical else 4
    return title, truncate("\n".join(lines), MAX_BYTES), priority, tags


def build_clear(report, osv_error):
    """All-clear report: the scan ran, but no critical/high vulnerability was found."""
    summary = report.get("summary", {})
    severity = summary.get("severity", {})
    osv = report.get("osv") or {}
    osv_enabled = bool(osv.get("enabled"))
    lines = ["Verdaccio SBOM scan finished",
             f"Scan time: {report.get('generated_at', 'unknown')}",
             f"Packages: {summary.get('unique_packages', 0)} unique / {summary.get('package_versions', 0)} versions",
             f"Tarballs hashed: {summary.get('tarballs_scanned', 0)} (oversize skipped: {summary.get('tarballs_skipped_oversize', 0)})",
             f"Dependency edges: {summary.get('dependency_edges', 0)}",
             f"Findings: CRITICAL={severity.get('CRITICAL', 0)} HIGH={severity.get('HIGH', 0)} "
             f"MEDIUM={severity.get('MEDIUM', 0)} LOW={severity.get('LOW', 0)}",
             f"Vulnerable versions: {summary.get('versions_with_vulnerabilities', 0)} / {summary.get('package_versions', 0)}"]
    if not osv_enabled:
        lines.append("OSV lookup disabled: no vulnerability lookup was performed in this run.")
        title = "SBOM scan finished (OSV disabled)"
        priority, tags = 2, ["white_check_mark", "grey_question"]
    elif osv_error:
        lines.append(f"OSV lookup FAILED: {osv_error}")
        lines.append("WARNING: this run is incomplete, an empty result is NOT evidence of zero vulnerabilities.")
        title = "SBOM scan INCOMPLETE (OSV error)"
        priority, tags = 3, ["rotating_light", "skull"]
    else:
        lines.append("Result: no CRITICAL/HIGH vulnerabilities found.")
        title = "SBOM scan OK / 平安"
        priority, tags = 2, ["white_check_mark"]
    if PUBLIC_URL:
        lines.append("")
        lines.append(f"Report: {PUBLIC_URL}/")
    return title, truncate("\n".join(lines), MAX_BYTES), priority, tags


def header_value(value):
    """HTTP headers are latin-1 in urllib; send non-ASCII as raw UTF-8 bytes."""
    try:
        value.encode("latin-1")
        return value
    except UnicodeEncodeError:
        return value.encode("utf-8")


def send(title, message, priority, tags):
    url = endpoint()
    headers = {"Content-Type": "text/plain; charset=utf-8",
               "Title": header_value(title), "Priority": str(priority),
               "Tags": ",".join(tags),
               "User-Agent": "verdaccio-supply-chain/1.0"}
    if PUBLIC_URL:
        headers["Click"] = f"{PUBLIC_URL}/"
        headers["Actions"] = f"view, Open report, {PUBLIC_URL}/"
    data = message.encode("utf-8")
    error = None
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                response.read()
            log.info("ntfy alert published to %s: %s", url, title)
            return True
        except urllib.error.HTTPError as e:
            error = e
            if e.code in (400, 401, 403, 404, 413):
                break
        except Exception as e:
            error = e
        if attempt < RETRIES:
            time.sleep(2 ** attempt)
    log.warning("ntfy publish failed (%s): %s", url, error)
    return False


def notify(report):
    """Publish one notification per scan: a risk alert, or an all-clear report."""
    if not ENABLED:
        log.debug("ntfy disabled")
        return False
    scoped = SCOPE != "all"
    everything = collect(report)
    findings = [f for f in everything if f[4]] if scoped else everything
    hidden = len(everything) - len(findings)
    unknown = unresolved(report, scoped)
    severity = (report.get("summary") or {}).get("severity") or {}
    counted = (severity.get("CRITICAL", 0), severity.get("HIGH", 0))
    if findings and (counted[0] or counted[1]) and not counted[0] and not counted[1]:
        log.error("Summary reports no critical/high findings but %s advisories were collected, "
                  "the notification is based on the collected advisories", len(findings))
    if (severity.get("CRITICAL", 0) or severity.get("HIGH", 0)) and not findings:
        log.error("Summary reports CRITICAL=%s HIGH=%s but no advisory was collected, "
                  "not claiming an all clear", severity.get("CRITICAL"), severity.get("HIGH"))
        title = "SBOM risk alert (advisory details unavailable)"
        message = truncate("Verdaccio SBOM scan finished.\n"
                           f"Scan time: {report.get('generated_at', 'unknown')}\n"
                           f"Findings: CRITICAL={severity.get('CRITICAL', 0)} HIGH={severity.get('HIGH', 0)} "
                           f"MEDIUM={severity.get('MEDIUM', 0)} LOW={severity.get('LOW', 0)}\n"
                           "The affected package versions could not be listed, see the report for details.",
                           MAX_BYTES)
        return send(title, message, 5, ["rotating_light"])
    if findings:
        sig = signature(findings)
        if MODE == "changed" and read_state().get("signature") == sig:
            log.info("ntfy risk alert skipped: findings unchanged since last alert")
            return False
        title, message, priority, tags = build(report, findings, hidden)
        ok = send(title, message, priority, tags)
        if ok:
            write_state(sig)
        return ok
    osv_error = (report.get("osv") or {}).get("error")
    if unknown:
        ids = ", ".join(sorted({str(v.get("id", "UNKNOWN")) for v in unknown})[:20])
        title = f"SBOM scan found {len(unknown)} advisories with unresolved severity"
        message = truncate("Verdaccio SBOM scan finished.\n"
                           f"Scan time: {report.get('generated_at', 'unknown')}\n"
                           f"Advisories: {len(unknown)} with unknown severity, no CRITICAL/HIGH classified\n"
                           f"IDs: {ids}\n"
                           "The severity of these advisories could not be resolved, so this run does "
                           "NOT confirm that there are no critical vulnerabilities.", MAX_BYTES)
        return send(title, message, 3, ["rotating_light", "question"])
    title, message, priority, tags = build_clear(report, osv_error)
    if hidden:
        message = truncate(message + f"\n{hidden} advisories exist in historical versions that are not "
                            "installed from this registry and were not counted.", MAX_BYTES)
    return send(title, message, priority, tags)


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s")
    log.info("ntfy endpoint: %s", endpoint())
