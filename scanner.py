#!/usr/bin/env python3
"""Read-only Verdaccio storage scanner; Python standard library only."""
import os, re, json, time, html, hashlib, tarfile, logging, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

ROOT = Path(os.getenv("SCAN_ROOT", "/verdaccio-data"))
OUT = Path(os.getenv("REPORT_DIR", "/reports"))
INTERVAL = max(1, int(os.getenv("SCAN_INTERVAL_HOURS", "24")))
OSV = os.getenv("OSV_ENABLED", "true").lower() not in ("0", "false", "no")
OSV_URL = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/querybatch")
BATCH = max(1, min(1000, int(os.getenv("OSV_BATCH_SIZE", "100"))))
TIMEOUT = max(5, int(os.getenv("OSV_TIMEOUT_SECONDS", "30")))
RETRIES = max(0, int(os.getenv("OSV_RETRIES", "2")))
MAX_BYTES = max(1, int(os.getenv("MAX_TARBALL_MB", "2048"))) * 1024 * 1024
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("supply-chain")
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

def now():
    return datetime.now(timezone.utc).isoformat()

def license_text(v):
    if isinstance(v, str): return v
    if isinstance(v, dict): return v.get("type", "UNKNOWN")
    if isinstance(v, list): return " AND ".join(license_text(x) for x in v)
    return "UNKNOWN"

def deps(v):
    return {str(k): str(x) for k, x in v.items()} if isinstance(v, dict) else {}

def read_json(p):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def add_packument(records, obj):
    if not isinstance(obj, dict) or not isinstance(obj.get("versions"), dict):
        return
    for ver, meta in obj["versions"].items():
        if not isinstance(meta, dict): continue
        name, version = meta.get("name") or obj.get("name"), meta.get("version") or ver
        if not isinstance(name, str) or not isinstance(version, str): continue
        key = name + "@" + version
        rec = records.setdefault(key, {"name": name, "version": version})
        rec.update({
            "description": meta.get("description", rec.get("description", "")),
            "license": license_text(meta.get("license")) if meta.get("license") else rec.get("license", "UNKNOWN"),
            "dependencies": deps(meta.get("dependencies")) or rec.get("dependencies", {}),
            "devDependencies": deps(meta.get("devDependencies")) or rec.get("devDependencies", {}),
            "optionalDependencies": deps(meta.get("optionalDependencies")) or rec.get("optionalDependencies", {}),
            "peerDependencies": deps(meta.get("peerDependencies")) or rec.get("peerDependencies", {}),
            "dist": meta.get("dist") if isinstance(meta.get("dist"), dict) else rec.get("dist", {}),
            "source": "metadata"
        })

def manifest_from_tgz(path):
    try:
        with tarfile.open(path, "r:gz") as tf:
            candidates = [m for m in tf.getmembers() if m.isfile() and m.name.endswith("package/package.json")]
            if not candidates: return None
            stream = tf.extractfile(min(candidates, key=lambda m: len(m.name)))
            raw = stream.read(2 * 1024 * 1024 + 1) if stream else b""
            if len(raw) > 2 * 1024 * 1024: return None
            obj = json.loads(raw.decode("utf-8"))
            return obj if isinstance(obj, dict) else None
    except Exception:
        return None

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()

def discover():
    records = {}
    for p in ROOT.rglob("*.json"):
        obj = read_json(p)
        add_packument(records, obj)
    for p in ROOT.rglob(".verdaccio-db.json"):
        add_packument(records, read_json(p))
    tarballs = skipped = 0
    for p in ROOT.rglob("*.tgz"):
        try:
            if p.stat().st_size > MAX_BYTES:
                skipped += 1
                log.warning("Tarball exceeds MAX_TARBALL_MB, skipped: %s", p)
                continue
            manifest = manifest_from_tgz(p)
            if not manifest or not isinstance(manifest.get("name"), str) or not isinstance(manifest.get("version"), str):
                log.warning("Cannot identify tarball package/version: %s", p)
                continue
            name, ver = manifest["name"], manifest["version"]
            rec = records.setdefault(name + "@" + ver, {"name": name, "version": ver})
            rec.setdefault("description", manifest.get("description", ""))
            rec.setdefault("license", license_text(manifest.get("license")))
            for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                rec.setdefault(field, deps(manifest.get(field)))
            rec["tarball_path"] = str(p.relative_to(ROOT))
            rec["tarball_size"] = p.stat().st_size
            rec["sha256"] = sha256(p)
            rec["tarball_file"] = p.name
            tarballs += 1
        except OSError as e:
            log.warning("Cannot scan %s: %s", p, e)
    return records, tarballs, skipped

def severity(v):
    for item in v.get("severity", []) or []:
        score = item.get("score")
        try:
            n = float(score)
            return "CRITICAL" if n >= 9 else "HIGH" if n >= 7 else "MEDIUM" if n >= 4 else "LOW"
        except (TypeError, ValueError):
            pass
    s = (v.get("database_specific") or {}).get("severity", "UNKNOWN")
    return s.upper() if isinstance(s, str) and s.upper() in RANK else "UNKNOWN"

def query_osv(batch):
    payload = {"queries": [{"package": {"name": r["name"], "ecosystem": "npm"}, "version": r["version"]} for r in batch]}
    req = urllib.request.Request(OSV_URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "verdaccio-supply-chain/1.0"}, method="POST")
    error = None
    for attempt in range(RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                result = json.loads(response.read().decode())
            rows = result.get("results", [])
            if len(rows) != len(batch): raise ValueError("OSV response length mismatch")
            return [x.get("vulns", []) or [] for x in rows]
        except Exception as e:
            error = e
            if attempt < RETRIES: time.sleep(2 ** attempt)
    raise RuntimeError(str(error))

def scan_vulnerabilities(records):
    if not OSV: return 0, "OSV disabled"
    items = list(records.values())
    total, errors = 0, []
    for i in range(0, len(items), BATCH):
        group = items[i:i+BATCH]
        try:
            results = query_osv(group)
            for rec, vulns in zip(group, results):
                rec["vulnerabilities"] = [{
                    "id": v.get("id", "UNKNOWN"), "summary": (v.get("summary") or v.get("details") or "")[:500],
                    "severity": severity(v), "aliases": v.get("aliases", []),
                    "published": v.get("published"), "modified": v.get("modified"),
                    "references": [x.get("url") for x in v.get("references", []) if x.get("url")][:5]
                } for v in vulns]
                total += len(vulns)
        except Exception as e:
            msg = f"batch {i//BATCH+1}: {e}"
            errors.append(msg)
            for rec in group:
                rec["vulnerabilities"] = []
                rec["vulnerability_scan_error"] = str(e)
            log.exception("OSV batch failed")
    return total, "; ".join(errors) if errors else None

def build_report():
    start = time.monotonic()
    if not ROOT.is_dir(): raise FileNotFoundError(f"SCAN_ROOT is not a directory: {ROOT}")
    records, tarballs, skipped = discover()
    items = sorted(records.values(), key=lambda x: (x["name"].lower(), x["version"]))
    vuln_total, osv_error = scan_vulnerabilities(records)
    sev, licenses, names = Counter(), Counter(), set()
    edges = vulnerable = 0
    for r in items:
        names.add(r["name"])
        licenses[r.get("license", "UNKNOWN")] += 1
        edges += sum(len(r.get(k, {})) for k in ("dependencies", "optionalDependencies", "peerDependencies"))
        if r.get("vulnerabilities"): vulnerable += 1
        for v in r.get("vulnerabilities", []): sev[v.get("severity", "UNKNOWN")] += 1
    return {
        "schema": "verdaccio-supply-chain-report/v1", "generated_at": now(),
        "scan_mode": "full", "scan_root": str(ROOT),
        "summary": {"unique_packages": len(names), "package_versions": len(items),
          "tarballs_scanned": tarballs, "tarballs_skipped_oversize": skipped,
          "versions_with_vulnerabilities": vulnerable, "vulnerability_findings": vuln_total,
          "dependency_edges": edges, "severity": {k: sev[k] for k in RANK},
          "licenses": dict(licenses.most_common()), "duration_seconds": round(time.monotonic()-start, 2)},
        "osv": {"enabled": OSV, "error": osv_error}, "packages": items
    }

def esc(x):
    return html.escape(str(x if x is not None else ""), quote=True)

def render_html(report):
    s = report["summary"]
    cards = [("Unique packages", s["unique_packages"]), ("Package versions", s["package_versions"]),
      ("Tarballs hashed", s["tarballs_scanned"]), ("Vulnerable versions", s["versions_with_vulnerabilities"]),
      ("Vulnerability findings", s["vulnerability_findings"]), ("Dependency edges", s["dependency_edges"])]
    card_html = "".join(f'<div class="card"><small>{esc(k)}</small><strong>{v}</strong></div>' for k,v in cards)
    rows = []
    for r in report["packages"]:
        vulns = r.get("vulnerabilities", [])
        risk = max((v.get("severity", "UNKNOWN") for v in vulns), key=lambda x:RANK.get(x,0), default="NONE")
        vuln_html = "<br>".join(f'<a target="_blank" rel="noopener" href="{esc((v.get("references") or ["https://osv.dev/vulnerability/"+v["id"]])[0])}">{esc(v["id"])}</a> ({esc(v["severity"])})' for v in vulns) or "—"
        dep = ", ".join(f"{k}@{v}" for k,v in list(r.get("dependencies",{}).items())[:10])
        rows.append("<tr>" + "".join([
          f"<td>{esc(r['name'])}</td><td>{esc(r['version'])}</td>",
          f'<td><span class="risk {risk.lower()}">{risk}</span></td>',
          f"<td>{esc(r.get('license','UNKNOWN'))}</td><td>{esc(r.get('tarball_file','not found'))}</td>",
          f"<td><code>{esc(r.get('sha256','not calculated'))}</code></td><td>{esc(dep)}</td><td>{vuln_html}</td>"
        ]) + "</tr>")
    sev_html = "".join(f'<div class="card"><small>{k}</small><strong>{s["severity"][k]}</strong></div>' for k in RANK)
    notice = f'<p class="notice">OSV query warning: {esc(report["osv"]["error"])}</p>' if report["osv"].get("error") else ""
    body = "\n".join(rows) or '<tr><td colspan="8">No package versions found. Check the mounted storage path/layout.</td></tr>'
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verdaccio Supply Chain Security</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f3f5f9;color:#172033;font:14px/1.5 system-ui, sans-serif}}
header{{background:#172b4d;color:white;padding:25px max(20px,calc((100vw - 1450px)/2))}}header h1{{margin:0;font-size:24px}}header p{{color:#cbd6e8;margin:5px 0}}
main{{max-width:1450px;margin:22px auto;padding:0 18px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}}
.card,.panel{{background:white;border:1px solid #e3e8f0;border-radius:11px;padding:15px}}.card small{{display:block;color:#68758b}}.card strong{{display:block;font-size:26px;margin-top:4px}}
.panel{{margin-top:16px}}.toolbar{{display:flex;gap:10px;margin:12px 0}}input,select{{padding:10px;border:1px solid #ccd4e2;border-radius:8px}}input{{flex:1;min-width:200px}}
.tablewrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:1100px}}td,th{{padding:10px;border-bottom:1px solid #e5e9f0;text-align:left;vertical-align:top}}th{{background:#f8f9fc;color:#526078}}
code{{font-size:11px;overflow-wrap:anywhere}}a{{color:#315fbd}}.risk{{padding:2px 8px;border-radius:20px;background:#eef1f5;font-size:11px;font-weight:bold}}
.critical,.high{{background:#ffe3e3;color:#a51d2d}}.medium{{background:#fff0d4;color:#8a5700}}.low{{background:#e3f4e8;color:#176b37}}
.notice{{background:#fff8e8;padding:10px;border:1px solid #f0dfb4;border-radius:8px}}.meta{{color:#68758b;font-size:12px;margin-top:12px}}
</style></head><body><header><h1>Verdaccio Supply Chain Security</h1><p>Full registry scan · {esc(report["generated_at"])} · OSV {"enabled" if report["osv"]["enabled"] else "disabled"}</p></header>
<main><section class="cards">{card_html}</section><section class="panel"><h2>Vulnerability severity</h2><div class="cards">{sev_html}</div></section>
<section class="panel"><h2>Package inventory</h2><div class="toolbar"><input id="q" placeholder="Search package, version, hash, CVE…"><select id="risk"><option value="">All severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>NONE</option></select></div>
<div class="tablewrap"><table id="tbl"><thead><tr><th>Package</th><th>Version</th><th>Risk</th><th>License</th><th>Tarball</th><th>SHA256</th><th>Dependencies</th><th>Vulnerabilities</th></tr></thead><tbody>{body}</tbody></table></div>
<div class="meta">Duration: {s["duration_seconds"]}s · Oversized tarballs skipped: {s["tarballs_skipped_oversize"]} · JSON schema: {esc(report["schema"])}</div>{notice}</section></main>
<script>const q=document.getElementById('q'),risk=document.getElementById('risk');function f(){{for(const r of document.querySelectorAll('#tbl tbody tr')){{r.hidden=!(r.innerText.toLowerCase().includes(q.value.toLowerCase())&&(!risk.value||r.cells[2].innerText.trim()===risk.value));}}}}q.addEventListener('input',f);risk.addEventListener('change',f);</script></body></html>"""

def write_report(report):
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    jp, hp = OUT/f"report-{stamp}.json", OUT/f"report-{stamp}.html"
    jp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    hp.write_text(render_html(report), encoding="utf-8")
    for src, dst in ((jp, OUT/"latest.json"), (hp, OUT/"index.html")):
        tmp = dst.with_suffix(dst.suffix+".tmp")
        tmp.write_bytes(src.read_bytes())
        tmp.replace(dst)
    log.info("Reports written: %s ; %s", hp, jp)

def run():
    r = build_report()
    write_report(r)
    s = r["summary"]
    log.info("Scan complete: packages=%s versions=%s tarballs=%s findings=%s",
             s["unique_packages"], s["package_versions"], s["tarballs_scanned"], s["vulnerability_findings"])

if __name__ == "__main__":
    log.info("Scanner online: root=%s interval=%sh", ROOT, INTERVAL)
    if os.getenv("SCAN_ON_START", "true").lower() not in ("0", "false", "no"):
        try: run()
        except Exception: log.exception("Initial scan failed")
    while True:
        time.sleep(INTERVAL * 3600)
        try: run()
        except Exception: log.exception("Scheduled scan failed; retrying next interval")
