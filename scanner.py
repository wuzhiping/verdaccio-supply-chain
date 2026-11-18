#!/usr/bin/env python3
"""Read-only Verdaccio storage scanner; Python standard library only."""
import os, re, json, time, html, hashlib, tarfile, logging, shutil, resource, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

import report_server
import notifier
from scan_control import CONTROL, LOCK, REPORTS

ROOT = Path(os.getenv("SCAN_ROOT", "/verdaccio-data"))
OUT = Path(os.getenv("REPORT_DIR", "/reports"))
INTERVAL = max(1, int(os.getenv("SCAN_INTERVAL_HOURS", "24")))
OSV = os.getenv("OSV_ENABLED", "true").lower() not in ("0", "false", "no")
OSV_URL = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/querybatch")
BATCH = max(1, min(1000, int(os.getenv("OSV_BATCH_SIZE", "100"))))
TIMEOUT = max(5, int(os.getenv("OSV_TIMEOUT_SECONDS", "30")))
RETRIES = max(0, int(os.getenv("OSV_RETRIES", "2")))
BUDGET = max(0, int(os.getenv("OSV_TIME_BUDGET_SECONDS", "900")))
MAX_BYTES = max(1, int(os.getenv("MAX_TARBALL_MB", "2048"))) * 1024 * 1024
PAGE_SIZE = max(20, int(os.getenv("REPORT_PAGE_SIZE", "100")))
STATIC_HTML_MAX = max(0, int(os.getenv("REPORT_STATIC_HTML_MAX", "50000")))
ARCHIVE_KEEP = max(0, int(os.getenv("REPORT_ARCHIVE_KEEP", "2")))
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
    """Store dependencies as a compact string, a dict costs ~1 KB per record."""
    if not isinstance(v, dict): return ""
    return ",".join(f"{str(k)}@{str(x)}" for k, x in v.items())

def unpack_deps(value):
    """Rebuild the dependency mapping for the report output."""
    if isinstance(value, dict): return value
    if not value: return {}
    out = {}
    for item in value.split(","):
        if "@" in item:
            name, _, ver = item.partition("@")
            out[name] = ver
    return out

def dep_count(value):
    return len(value.split(",")) if isinstance(value, str) and value else 0

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

def read_manifest(tf):
    members = [m for m in tf.getmembers()
               if m.isfile() and m.name.endswith("package.json")
               and not m.name.split("/")[0].startswith("node_modules")]
    if not members: return None, "no package.json member"
    # npm uses "package/package.json", @types and older packages use "<name>/package.json"
    members.sort(key=lambda m: (m.name != "package/package.json", m.name.count("/"), len(m.name)))
    try:
        stream = tf.extractfile(members[0])
        raw = stream.read(2 * 1024 * 1024 + 1) if stream else b""
    except Exception as e:
        return None, f"cannot read manifest: {type(e).__name__}: {e}"
    if len(raw) > 2 * 1024 * 1024: return None, "manifest larger than 2 MiB"
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        return None, f"invalid manifest JSON: {e}"
    if not isinstance(obj, dict): return None, "manifest is not a JSON object"
    return obj, ""

def manifest_from_tgz(path):
    """Return (manifest, reason); manifest is None when the manifest cannot be read."""
    errors = []
    for mode in ("r:gz", "r:*"):
        try:
            with tarfile.open(path, mode) as tf:
                return read_manifest(tf)
        except Exception as e:
            errors.append(f"{mode}: {type(e).__name__}: {e}")
    return None, "; ".join(errors)

def progress(phase, current, total, message=""):
    """Publish scan progress for the status API and log it periodically."""
    CONTROL.set_progress(phase, current, total, message)
    LOCK.heartbeat()
    if total:
        step = max(1, total // 20)
        if current == total or current % step == 0:
            log.info("Scan progress: %s %s/%s (%.1f%%) %s", phase, current, total,
                     current * 100.0 / total, message)

def identify_from_path(path, records=None):
    """Derive name@version from the registry layout, e.g. @scope/pkg/pkg-1.0.0.tgz."""
    try:
        parts = path.relative_to(ROOT).parts
    except ValueError:
        parts = path.parts
    if len(parts) < 2: return None
    filename = parts[-1]
    if not filename.endswith(".tgz"): return None
    dirs = list(parts[:-1])
    if dirs and dirs[-1] == "-": dirs.pop()
    if not dirs: return None
    name = dirs[-2] + "/" + dirs[-1] if len(dirs) >= 2 and dirs[-2].startswith("@") else dirs[-1]
    base = name.split("/")[-1]
    stem = filename[:-4]
    if stem.startswith(base + "-"):
        version = stem[len(base) + 1:]
        if version: return name, version
    if records:
        version = stem.rsplit("-", 1)[-1]
        if version and f"{name}@{version}" in records: return name, version
    return None

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()

def discover():
    records = {}
    json_files = list(ROOT.rglob("*.json"))
    progress("discovering", 0, len(json_files), "reading package metadata")
    for i, p in enumerate(json_files, 1):
        add_packument(records, read_json(p))
        if i % 250 == 0:
            progress("discovering", i, len(json_files), f"{len(records)} package versions")
    for p in ROOT.rglob(".verdaccio-db.json"):
        add_packument(records, read_json(p))
    tarballs = skipped = 0
    tgz_files = list(ROOT.rglob("*.tgz"))
    for i, p in enumerate(tgz_files, 1):
        try:
            if p.stat().st_size > MAX_BYTES:
                skipped += 1
                log.warning("Tarball exceeds MAX_TARBALL_MB, skipped: %s", p)
                continue
            manifest, reason = manifest_from_tgz(p)
            name = ver = None
            if isinstance(manifest, dict):
                name, ver = manifest.get("name"), manifest.get("version")
            if not isinstance(name, str) or not isinstance(ver, str):
                fallback = identify_from_path(p, records)
                if fallback:
                    name, ver = fallback
                    log.warning("Tarball manifest unreadable (%s), package identified from path: %s@%s",
                                reason, name, ver)
                else:
                    log.warning("Cannot identify tarball package/version (%s): %s", reason, p)
                    continue
            rec = records.setdefault(name + "@" + ver, {"name": name, "version": ver})
            if isinstance(manifest, dict):
                rec.setdefault("description", manifest.get("description", ""))
                rec.setdefault("license", license_text(manifest.get("license")))
                for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                    rec.setdefault(field, deps(manifest.get(field)))
            else:
                rec["tarball_manifest_error"] = reason
            rec["tarball_path"] = str(p.relative_to(ROOT))
            rec["tarball_size"] = p.stat().st_size
            rec["sha256"] = sha256(p)
            rec["tarball_file"] = p.name
            tarballs += 1
        except OSError as e:
            log.warning("Cannot scan %s: %s", p, e)
        finally:
            progress("hashing", i, len(tgz_files), p.name)
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
    started = time.monotonic()
    deadline = started + BUDGET if BUDGET else None
    for i in range(0, len(items), BATCH):
        if deadline and time.monotonic() > deadline:
            remaining = items[i:]
            for rec in remaining:
                rec["vulnerabilities"] = []
                rec["vulnerability_scan_error"] = "not queried, OSV time budget exhausted"
            errors.append(f"time budget of {BUDGET}s exhausted, {len(remaining)} package versions not queried")
            log.warning("OSV time budget exhausted, %s package versions not queried", len(remaining))
            break
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
        progress("osv", i + len(group), len(items),
                 f"{len(items)} package versions, {round(time.monotonic() - started, 1)}s elapsed")
    return total, "; ".join(errors) if errors else None

def summarize(report):
    """Recompute the summary counters from the package list."""
    sev, licenses, names = Counter(), Counter(), set()
    edges = vulnerable = 0
    for r in report["packages"]:
        names.add(r["name"])
        licenses[r.get("license", "UNKNOWN")] += 1
        edges += sum(dep_count(r.get(k, "")) for k in ("dependencies", "optionalDependencies", "peerDependencies"))
        if r.get("vulnerabilities"): vulnerable += 1
        for v in r.get("vulnerabilities", []): sev[v.get("severity", "UNKNOWN")] += 1
    report["summary"].update({
        "unique_packages": len(names), "package_versions": len(report["packages"]),
        "versions_with_vulnerabilities": vulnerable, "vulnerability_findings": sum(sev.values()),
        "dependency_edges": edges, "severity": {k: sev[k] for k in RANK},
        "licenses": dict(licenses.most_common())})

def build_report(records, tarballs, skipped):
    items = sorted(records.values(), key=lambda x: (x["name"].lower(), x["version"]))
    report = {
        "schema": "verdaccio-supply-chain-report/v1", "generated_at": now(),
        "scan_mode": "full", "scan_root": str(ROOT), "scan_state": "complete",
        "summary": {"unique_packages": 0, "package_versions": len(items),
          "tarballs_scanned": tarballs, "tarballs_skipped_oversize": skipped,
          "versions_with_vulnerabilities": 0, "vulnerability_findings": 0,
          "dependency_edges": 0, "severity": {k: 0 for k in RANK},
          "vulnerability_scan_incomplete": False, "licenses": {}, "duration_seconds": 0},
        "osv": {"enabled": OSV, "error": None, "packages_queried": 0, "packages_failed": 0},
        "packages": items}
    summarize(report)
    return report

def human_size(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024: return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"

def peak_memory_mb():
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)

def esc(x):
    return html.escape(str(x if x is not None else ""), quote=True)

def render_html(report, out):
    """Write the HTML report incrementally, the report can be very large."""
    s = report["summary"]
    pending = report.get("scan_state") == "pending"
    cards = [("Unique packages", s["unique_packages"]), ("Package versions", s["package_versions"]),
      ("Tarballs hashed", s["tarballs_scanned"]),
      ("Vulnerable versions", "—" if pending else s["versions_with_vulnerabilities"]),
      ("Vulnerability findings", "—" if pending else s["vulnerability_findings"]),
      ("Dependency edges", s["dependency_edges"])]
    card_html = "".join(f'<div class="card"><small>{esc(k)}</small><strong>{esc(v)}</strong></div>' for k,v in cards)
    def rows():
        for r in report["packages"]:
            vulns = r.get("vulnerabilities", [])
            risk = max((v.get("severity", "UNKNOWN") for v in vulns), key=lambda x:RANK.get(x,0), default="PENDING" if pending else "NONE")
            vuln_html = "<br>".join(f'<a target="_blank" rel="noopener" href="{esc((v.get("references") or ["https://osv.dev/vulnerability/"+v["id"]])[0])}">{esc(v["id"])}</a> ({esc(v["severity"])})' for v in vulns) or ('<span class="pending">PENDING</span>' if pending else "—")
            dep = ", ".join(r.get("dependencies", "").split(",")[:5]) if isinstance(r.get("dependencies"), str) else \
                  ", ".join(f"{k}@{v}" for k,v in list(r.get("dependencies",{}).items())[:5])
            yield "<tr>" + "".join([
              f"<td>{esc(r['name'])}</td><td>{esc(r['version'])}</td>",
              f'<td><span class="risk {risk.lower()}">{risk}</span></td>',
              f"<td>{esc(r.get('license','UNKNOWN'))}</td><td>{esc(r.get('tarball_file','not found'))}</td>",
              f"<td><code>{esc(r.get('sha256','not calculated'))}</code></td><td>{esc(dep)}</td><td>{vuln_html}</td>"
            ]) + "</tr>"
    sev_html = "".join(f'<div class="card"><small>{k}</small><strong>{"—" if pending else s["severity"][k]}</strong></div>' for k in RANK)
    if pending:
        notice = '<p class="notice">Scan in progress &middot; vulnerability lookup is still pending &middot; this document contains the package inventory only</p>'
    elif report["osv"].get("error"):
        notice = f'<p class="notice">OSV query warning: {esc(report["osv"]["error"])}</p>'
    else:
        notice = ""
    if True:
        out.write(f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
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
.pending{{color:#8a5700;font-size:11px;font-weight:bold}}
</style></head><body><header><h1>Verdaccio Supply Chain Security</h1><p>Full registry scan · {esc(report["generated_at"])} · OSV {"enabled" if report["osv"]["enabled"] else "disabled"}</p></header>
<main><section class="cards">{card_html}</section><section class="panel"><h2>Vulnerability severity</h2><div class="cards">{sev_html}</div></section>
<section class="panel"><h2>Package inventory</h2><div class="toolbar"><input id="q" placeholder="Search package, version, hash, CVE…"><select id="risk"><option value="">All severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>MEDIUM</option><option>LOW</option><option>NONE</option><option>PENDING</option></select><button id="prev" type="button">Prev</button><button id="next" type="button">Next</button><span id="pager" class="meta"></span></div>
<div class="tablewrap"><table id="tbl"><thead><tr><th>Package</th><th>Version</th><th>Risk</th><th>License</th><th>Tarball</th><th>SHA256</th><th>Dependencies</th><th>Vulnerabilities</th></tr></thead><tbody>""")
        for row in rows():
            out.write(row)
        if not rows:
            out.write('<tr><td colspan="8">No package versions found. Check the mounted storage path/layout.</td></tr>')
        out.write(f"""</tbody></table></div>
<div class="meta">Duration: {s["duration_seconds"]}s · Oversized tarballs skipped: {s["tarballs_skipped_oversize"]} · JSON schema: {esc(report["schema"])}</div>{notice}</section></main>
<script>
const q=document.getElementById('q'),risk=document.getElementById('risk'),pager=document.getElementById('pager');
const rows=Array.prototype.slice.call(document.querySelectorAll('#tbl tbody tr'));
const text=rows.map(function(r){{return r.textContent.toLowerCase();}});
const sev=rows.map(function(r){{return r.cells[2]?r.cells[2].textContent.trim():'';}});
const PER={PAGE_SIZE};let page=1;
function apply(){{
  const qv=q.value.trim().toLowerCase(),rv=risk.value,hits=[];
  for(let i=0;i<rows.length;i++){{if((!qv||text[i].indexOf(qv)>=0)&&(!rv||sev[i]===rv))hits.push(i);}}
  const pages=Math.max(1,Math.ceil(hits.length/PER));if(page>pages)page=pages;
  for(let i=0;i<rows.length;i++)rows[i].style.display='none';
  const from=(page-1)*PER,to=Math.min(from+PER,hits.length);
  for(let k=from;k<to;k++)rows[hits[k]].style.display='';
  pager.textContent='第 '+page+' / '+pages+' 页 · 命中 '+hits.length+' / '+rows.length+' 条';
}}
function debounce(fn,ms){{let t;return function(){{clearTimeout(t);t=setTimeout(fn,ms);}};}}
q.addEventListener('input',debounce(function(){{page=1;apply();}},120));
risk.addEventListener('change',function(){{page=1;apply();}});
document.getElementById('prev').addEventListener('click',function(){{if(page>1){{page--;apply();}}}});
document.getElementById('next').addEventListener('click',function(){{page++;apply();}});
apply();
</script></body></html>""")

def json_ready(record):
    """Rebuild the report schema for one package (dependencies back to objects)."""
    out = dict(record)
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if field in out: out[field] = unpack_deps(out[field])
    return out

def write_json(report, path):
    """Stream the JSON report so a huge report never becomes one giant string."""
    with path.open("w", encoding="utf-8") as fh:
        fh.write("{\n")
        for key in ("schema", "generated_at", "scan_mode", "scan_root", "scan_state"):
            if key in report:
                fh.write(f"  {json.dumps(key)}: {json.dumps(report[key], ensure_ascii=False)},\n")
        summary = json.dumps(report["summary"], ensure_ascii=False, indent=2)
        fh.write(f'  "summary": {summary},\n')
        fh.write(f'  "osv": {json.dumps(report["osv"], ensure_ascii=False)},\n')
        fh.write('  "packages": [\n')
        packages = report["packages"]
        for i, rec in enumerate(packages):
            fh.write("    " + json.dumps(json_ready(rec), ensure_ascii=False))
            fh.write(",\n" if i < len(packages) - 1 else "\n")
        fh.write("  ]\n}\n")

def prune_archives():
    files = sorted(OUT.glob("report-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[ARCHIVE_KEEP:]:
        try:
            old.unlink()
            html = old.with_suffix(".html")
            if html.exists(): html.unlink()
        except OSError:
            pass

def write_report(report):
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    jp, hp = OUT/f"report-{stamp}.json", OUT/f"report-{stamp}.html"
    write_json(report, jp)
    count = len(report["packages"])
    if STATIC_HTML_MAX and count > STATIC_HTML_MAX:
        log.info("Static HTML skipped for %s package versions (limit %s), use the report portal",
                 count, STATIC_HTML_MAX)
    else:
        with hp.open("w", encoding="utf-8") as fh:
            render_html(report, fh)
    # latest.json as a hard link, no second copy of a possibly huge file
    for src, dst in ((jp, OUT/"latest.json"), (hp, OUT/"index.html")):
        if not src.exists(): continue
        tmp = dst.with_name(dst.name + ".tmp")
        try:
            tmp.unlink()
        except OSError:
            pass
        try:
            os.link(src, tmp)
        except OSError:
            shutil.copyfile(src, tmp)
        try:
            dst.unlink()
        except OSError:
            pass
        tmp.replace(dst)
    prune_archives()
    log.info("Reports written: %s (%s) ; %s (%s)", hp.name, human_size(hp.stat().st_size) if hp.exists() else "-",
             jp.name, human_size(jp.stat().st_size))

def run():
    if LOCK.held_by_other() and LOCK.owner_alive():
        log.warning("Another scanner is active on this report directory, skipping this scan")
        CONTROL.end(error="another scanner is active")
        return
    LOCK.claim()
    CONTROL.begin()
    started = time.monotonic()
    try:
        if not ROOT.is_dir(): raise FileNotFoundError(f"SCAN_ROOT is not a directory: {ROOT}")
        progress("scanning", 0, 0, "scanning storage")
        records, tarballs, skipped = discover()
        r = build_report(records, tarballs, skipped)
        r["scan_state"] = "pending"
        r["osv"]["error"] = "vulnerability lookup pending"
        r["summary"]["vulnerability_scan_incomplete"] = True
        r["summary"]["duration_seconds"] = round(time.monotonic() - started, 2)
        progress("reporting", 1, 1, "writing inventory report")
        write_report(r)
        log.info("Inventory report written, %s package versions, peak_rss=%sMB", len(records), peak_memory_mb())
        progress("osv", 0, len(records), "vulnerability lookup")
        vuln_total, osv_error = scan_vulnerabilities(records)
        r["scan_state"] = "complete"
        r["osv"]["error"] = osv_error
        r["summary"]["vulnerability_findings"] = vuln_total
        r["summary"]["vulnerability_scan_incomplete"] = bool(osv_error)
        summarize(r)
        r["summary"]["duration_seconds"] = round(time.monotonic() - started, 2)
        progress("reporting", 1, 1, "writing report")
        REPORTS.set(r)
        write_report(r)
        s = r["summary"]
        log.info("Scan complete: packages=%s versions=%s tarballs=%s findings=%s peak_rss=%sMB",
                 s["unique_packages"], s["package_versions"], s["tarballs_scanned"],
                 s["vulnerability_findings"], peak_memory_mb())
        try:
            progress("notifying", 1, 1, "publishing notifications")
            notifier.notify(r)
        except Exception:
            log.exception("Risk notification failed")
        CONTROL.end(summary=s, generated_at=r["generated_at"])
    except Exception as e:
        CONTROL.end(error=str(e))
        raise

def main():
    log.info("Scanner online: root=%s interval=%sh", ROOT, INTERVAL)
    try:
        report_server.start_server()
    except Exception:
        log.exception("Report HTTP server failed to start")
    if os.getenv("SCAN_ON_START", "true").lower() not in ("0", "false", "no"):
        try: run()
        except Exception: log.exception("Initial scan failed")
    deadline = time.monotonic() + INTERVAL * 3600
    while True:
        triggered = CONTROL.trigger.wait(max(1.0, deadline - time.monotonic()))
        if triggered:
            CONTROL.trigger.clear()
        try: run()
        except Exception: log.exception("Scan failed; next attempt on schedule")
        if triggered:
            deadline += INTERVAL * 3600
            if deadline <= time.monotonic():
                deadline = time.monotonic() + INTERVAL * 3600
        else:
            deadline = time.monotonic() + INTERVAL * 3600

if __name__ == "__main__":
    main()
