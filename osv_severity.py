#!/usr/bin/env python3
"""Severity classification and enrichment for OSV advisories; standard library only."""
import os, re, json, html, logging, urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

log = logging.getLogger("supply-chain.severity")

API_URL = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/querybatch").rstrip("/")
DETAIL_URL = os.getenv("OSV_DETAIL_URL", API_URL.rsplit("/", 1)[0]).rstrip("/")
WEB_URL = os.getenv("OSV_WEB_URL", "https://osv.dev/vulnerability").rstrip("/")
ENRICH = os.getenv("OSV_ENRICH", "true").lower() not in ("0", "false", "no")
TIMEOUT = max(3, int(os.getenv("OSV_DETAIL_TIMEOUT_SECONDS", "15")))
MAX_FETCH = max(0, int(os.getenv("OSV_ENRICH_MAX", "5000")))
WORKERS = max(1, int(os.getenv("OSV_ENRICH_WORKERS", "8")))

RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
LABELS = {"MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "IMPORTANT": "HIGH", "SEVERE": "HIGH",
          "CRITICAL": "CRITICAL", "HIGH": "HIGH", "LOW": "LOW", "NONE": "NONE"}

CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
CVSS_AC = {"L": 0.77, "H": 0.44}
CVSS_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
CVSS_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
CVSS_UI = {"N": 0.85, "R": 0.62}
CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

WEB_LEVEL = re.compile(r'severity-level severity-(\w+)"[^>]*>\s*([\d.]+)')
WEB_VECTOR = re.compile(r'CVSS:3\.\d/[A-Z]+:[A-Z0-9]+(?:/[A-Z]+:[A-Z0-9]+)+')
WEB_SUMMARY = re.compile(r'<dt class="summary">Summary</dt>\s*<dd class="summary[^"]*">(.*?)</dd>', re.S)
WEB_SPECIFIC = re.compile(r'<pre class="specific">(.*?)</pre>', re.S)

_CACHE = {}


def level_of(score):
    try:
        n = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if n >= 9:
        return "CRITICAL"
    if n >= 7:
        return "HIGH"
    if n >= 4:
        return "MEDIUM"
    if n > 0:
        return "LOW"
    return "NONE"


def roundup(value):
    """CVSS 3.1 Roundup function."""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (scaled // 10000 + 1) / 10.0


def cvss_base_score(vector):
    """CVSS v3.0/v3.1 base score from a vector string; None when not parsable."""
    if not isinstance(vector, str) or not vector.upper().startswith("CVSS:3"):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        key, sep, value = part.partition(":")
        if sep:
            metrics[key.strip().upper()] = value.strip().upper()
    try:
        av = CVSS_AV[metrics["AV"]]
        ac = CVSS_AC[metrics["AC"]]
        scope = metrics["S"]
        pr = (CVSS_PR_C if scope == "C" else CVSS_PR_U)[metrics["PR"]]
        ui = CVSS_UI[metrics["UI"]]
        c, i, a = CVSS_CIA[metrics["C"]], CVSS_CIA[metrics["I"]], CVSS_CIA[metrics["A"]]
    except KeyError:
        return None
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    score = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return roundup(min(score, 10))


def severity_from_api(vuln):
    """Highest severity signal available in an OSV API record."""
    levels = []
    for item in (vuln.get("severity") or []):
        score = item.get("score")
        if score is None:
            continue
        try:
            levels.append(level_of(float(score)))
            continue
        except (TypeError, ValueError):
            pass
        base = cvss_base_score(str(score))
        if base is not None:
            levels.append(level_of(base))
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        mapped = LABELS.get(label.strip().upper())
        if mapped:
            levels.append(mapped)
    if not levels:
        return "UNKNOWN"
    return max(levels, key=lambda x: RANK.get(x, 0))


def parse_web(page):
    """Extract severity, score and summary from an osv.dev advisory page."""
    out = {}
    match = WEB_LEVEL.search(page)
    if match:
        out["severity"] = LABELS.get(match.group(1).upper(), "UNKNOWN")
        try:
            out["score"] = float(match.group(2))
        except ValueError:
            pass
    match = WEB_VECTOR.search(page)
    if match:
        base = cvss_base_score(match.group(0))
        if base is not None:
            out["score"] = max(out.get("score", 0), base)
            level = level_of(base)
            if RANK.get(level, 0) > RANK.get(out.get("severity", "UNKNOWN"), 0):
                out["severity"] = level
    match = WEB_SPECIFIC.search(page)
    if match:
        try:
            data = json.loads(html.unescape(match.group(1)))
            mapped = LABELS.get(str(data.get("severity", "")).upper())
            if mapped and RANK.get(mapped, 0) > RANK.get(out.get("severity", "UNKNOWN"), 0):
                out["severity"] = mapped
        except Exception:
            pass
    match = WEB_SUMMARY.search(page)
    if match:
        text = html.unescape(re.sub(r"<[^>]+>", "", match.group(1))).strip()
        if text:
            out["summary"] = text[:500]
    return out


def fetch_detail(vid):
    """Full advisory record from the OSV detail endpoint (same host as the query API)."""
    req = urllib.request.Request(f"{DETAIL_URL}/vulns/{quote(vid)}",
                                 headers={"User-Agent": "verdaccio-supply-chain/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode())


def fetch_web(vid):
    """Fallback: scrape the severity from the advisory page."""
    req = urllib.request.Request(f"{WEB_URL}/{quote(vid)}",
                                 headers={"User-Agent": "verdaccio-supply-chain/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        return parse_web(response.read(2 * 1024 * 1024).decode("utf-8", "ignore"))


def lookup(vid):
    """Resolve one advisory id to severity, score and summary."""
    try:
        record = fetch_detail(vid)
        data = {"severity": severity_from_api(record)}
        score = None
        for item in (record.get("severity") or []):
            try:
                score = float(item.get("score"))
                break
            except (TypeError, ValueError):
                base = cvss_base_score(str(item.get("score", "")))
                if base is not None:
                    score = base
                    break
        if score is not None:
            data["score"] = score
        if record.get("summary"):
            data["summary"] = record["summary"][:500]
        if record.get("references"):
            data["url"] = record["references"][0].get("url")
        return data
    except Exception as e:
        log.debug("Detail lookup failed for %s: %s", vid, e)
    try:
        return fetch_web(vid)
    except Exception as e:
        log.warning("Severity enrichment failed for %s: %s", vid, e)
        return {}


def enrich(items):
    """Fill severity/summary for advisories returned without severity data."""
    if not ENRICH:
        return 0
    pending = []
    for item in items:
        vid = str(item.get("id") or "")
        if vid and vid != "UNKNOWN" and item.get("severity", "UNKNOWN") == "UNKNOWN" and vid not in _CACHE:
            if vid not in pending:
                pending.append(vid)
    if not pending:
        return 0
    if MAX_FETCH and len(pending) > MAX_FETCH:
        log.warning("Severity enrichment limited to %s advisories, %s stay UNKNOWN", MAX_FETCH, len(pending) - MAX_FETCH)
        pending = pending[:MAX_FETCH]
    log.info("Resolving severity for %s advisories via %s", len(pending), DETAIL_URL)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for vid, data in zip(pending, pool.map(lookup, pending)):
            _CACHE[vid] = data
    changed = 0
    for item in items:
        vid = str(item.get("id") or "")
        data = _CACHE.get(vid)
        if not data:
            continue
        if data.get("severity") and item.get("severity", "UNKNOWN") == "UNKNOWN":
            item["severity"] = data["severity"]
            changed += 1
        if data.get("score") and not item.get("cvss_score"):
            item["cvss_score"] = data["score"]
        if data.get("summary") and not item.get("summary"):
            item["summary"] = data["summary"]
        if data.get("url") and not item.get("references"):
            item["references"] = [data["url"]]
    return changed
