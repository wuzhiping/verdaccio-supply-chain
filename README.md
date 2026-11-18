# Verdaccio Supply Chain Security Scanner

Read-only scheduled scanner for Verdaccio npm storage. Python uses only its standard library.

## Deploy

1. Unzip this project on the Docker host.
2. Copy `.env.example` to `.env` and set `VERDACCIO_DATA` to the host's actual `storage/data/` directory.
3. Run:

```bash
cp .env.example .env
# Edit .env: VERDACCIO_DATA=/opt/verdaccio/storage/data
docker compose -f compose.yml up -d --build
docker compose -f compose.yml logs -f
```

The scanner runs a full scan on startup, then every 24 hours. Reports are published over HTTP on port `8080` inside the container and mapped to the host by `compose.yml`, so the latest report is at `http://<host>:8080/` (`reports/index.html`).

## Sharing the reports over HTTP

The container serves the report directory with a read-only static server (Python standard library only, no extra dependencies):

| Path | Content |
|------|---------|
| `/` | Latest report (`index.html`) |
| `/latest.json` | Latest report as JSON |
| `/report-<timestamp>.html` / `.json` | Archived reports |
| `/healthz` | JSON health probe (`{"status":"ok",...}`) |
| `/api/scan` | Trigger a scan (`POST`) / read scan state (`GET`) |

Access control is optional but recommended, since package inventories and vulnerability findings are sensitive:

```bash
# .env
REPORT_TOKEN=$(openssl rand -hex 16)
```

With a token set, every request needs it:

```bash
curl -H "Authorization: Bearer $REPORT_TOKEN" http://<host>:8080/
curl "http://<host>:8080/latest.json?token=$REPORT_TOKEN"
```

Opening `http://<host>:8080/?token=<token>` in a browser stores the token in an `HttpOnly` cookie and redirects to the clean URL, so the pages can be browsed normally. Without `REPORT_TOKEN` the portal is open to anyone who can reach the port.

For public exposure, keep the token and terminate TLS in front of the port (the built-in server speaks plain HTTP only):

```bash
docker compose -f compose.yml up -d --build
docker compose -f compose.yml logs -f
```

## Reverse proxy (subdirectory)

The service works behind a reverse proxy, also when it is mounted under a path prefix such as `https://host/sbom/`:

- The progress page resolves the API relative to its own URL (`new URL('api/scan', location.href)`), so it keeps working under any prefix.
- API routes (`/api/scan`, `/api/scan/status`, `/progress`, `/healthz`) are matched by path suffix, and report files are looked up by suffix as well, so the proxy may either strip the prefix (`proxy_pass http://backend/`) or keep it.
- The token cookie is issued with `Path=/`, so it is sent for every proxied path.

```nginx
location /sbom/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

## Triggering a scan over REST

The HTTP service also exposes a small REST API to start a scan on demand:

| Method & Path | Response | Meaning |
|---------------|----------|---------|
| `POST /api/scan` | `202 Accepted` | Scan triggered, running in the background |
| `POST /api/scan` | `429 Too Many Requests` | A scan is already running (`Retry-After` header included) |
| `GET /api/scan` | `200 OK` | Current state (`phase`, `running`, timings, last summary) |
| `GET /api/scan/status` | `200 OK` | Alias of `GET /api/scan` |
| `GET /progress` | `200 OK` | Live progress page (auto-refreshing, has a "Run scan now" button) |
| `GET /healthz` | `200 OK` | Health probe |

```bash
# trigger a scan now
curl -X POST http://<host>:8080/api/scan

# poll the state
curl -s http://<host>:8080/api/scan | python3 -m json.tool
```

`GET /api/scan` also carries the live `progress` object:

```json
{"phase": "idle", "running": true, "elapsed_seconds": 3.1,
 "progress": {"phase": "hashing", "current": 10, "total": 12, "percent": 83.3,
              "message": "big6-1.0.0.tgz", "updated_at": "2026-11-18T07:08:12+00:00"}}
```

Phases are `discovering` (package metadata) → `hashing` (tarball identity) → `reporting` (inventory written) → `osv` (vulnerability lookup) → `reporting` (final report) → `notifying` → `completed`. The same progress is written to the log every 5% as `Scan progress: hashing 150/300 (50.0%) …`.

The inventory report is written **before** the vulnerability lookup starts, so the portal always shows the package inventory even when the OSV phase is slow or fails. While the lookup is pending the report is marked `scan_state: pending`: the vulnerability cards and the risk column show `—` / `PENDING` and a banner explains that the document contains the inventory only — pending data is never presented as "no vulnerabilities". The vulnerability lookup is bounded by `OSV_TIME_BUDGET_SECONDS` (900s by default); when the budget is exhausted the remaining packages are marked as not queried and the report is flagged as incomplete.

### OSV endpoint cost

A failing OSV endpoint is the usual reason for a scan that never finishes: each batch of 100 packages is retried `OSV_RETRIES` times with `OSV_TIMEOUT_SECONDS` per attempt, so an unreachable endpoint costs `retries+1 × timeout` per batch (93s with the defaults) and a large registry takes hours. Keep `OSV_API_URL` pointing at a reachable endpoint (the bundled default is the local mirror, ~0.5s per batch) and lower `OSV_TIMEOUT_SECONDS` / `OSV_RETRIES` so a broken endpoint is detected quickly.

### Two scanners on the same storage

A second scanner working on the same report directory is detected through a lock file (`REPORT_DIR/.scan.lock`):

- a scheduled scan skips with `Another scanner is active on this report directory` and does not touch the reports,
- `POST /api/scan` answers `429 {"error": "another_scanner_active"}`,
- the lock is refreshed while a scan runs, so a dead scanner is taken over automatically.

Set `SCAN_LOCK_STALE_SECONDS` (180) to change how long a lock is considered live.

Only one scan may run at a time. While a scan is in progress further triggers are rejected with `429` and the body `{"error": "scan_in_progress", ...}`; the rejected requests are counted in `requests_rejected`. The API uses the same `REPORT_TOKEN` as the report portal (send `Authorization: Bearer <token>` or `?token=<token>`), so trigger it with the same credential used to read the reports.

`phase` moves through `idle` → `requested` → `running` → `idle`. A triggered scan does not postpone the scheduled one: the daily deadline stays anchored to the last scheduled run.

## Risk alerts & scan status (ntfy)

Every finished scan publishes **one** notification to an ntfy server (no login, topic-only):

- **CRITICAL / HIGH findings** → risk alert, priority `5` (CRITICAL present) or `4`, tags `rotating_light` / `warning`, body lists every affected `name@version` with its advisory ID
- **No CRITICAL / HIGH findings** → all-clear report (平安), priority `2`, tag `white_check_mark`, body carries package/version counts, tarball hashes, dependency edges, severity totals and the report link
- **OSV lookup failed** → the all-clear is downgraded to `SBOM scan INCOMPLETE (OSV error)`, priority `3`, with an explicit warning that an empty result is not evidence of zero vulnerabilities

The target is configured entirely through environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `NTFY_ENABLED` | `true` | Master switch for push notifications |
| `NTFY_URL` | `https://msn.feg.cn` | ntfy server base URL; may also contain the topic |
| `NTFY_TOPIC` | `pub_abc` | Topic to publish to (appended to `NTFY_URL` unless the URL already ends with it) |
| `NTFY_ALERT_MODE` | `always` | `always` pushes the risk alert on every scan with findings, `changed` only when the finding set differs from the last alert (the all-clear report is always sent) |
| `NTFY_TIMEOUT_SECONDS` | `10` | Per-request timeout |
| `NTFY_RETRIES` | `2` | Retries on transient failures |
| `NTFY_MAX_MESSAGE_BYTES` | `3500` | Truncation limit for the message body |
| `NTFY_MAX_ITEMS` | `20` | Max packages listed per severity level |
| `REPORT_PUBLIC_URL` | empty | Public base URL of the report portal; used as the click-through link |

```bash
# .env
NTFY_URL=https://msn.feg.cn
NTFY_TOPIC=pub_abc
REPORT_PUBLIC_URL=https://sbom.example.internal
```

Priority is `5` when a CRITICAL finding exists, `4` for HIGH-only alerts, `3` for an incomplete scan and `2` for the all-clear report. Push failures are logged and never abort the scan.

## What it does

- Recursively discovers packument-style JSON with a `versions` object.
- Scans `.tgz` tarballs and reads `package/package.json`.
- Computes SHA-256 for identified local tarballs.
- Records dependencies, optional/peer dependencies, and license metadata.
- Queries OSV for each package/version using ecosystem `npm`.
- Writes timestamped HTML/JSON plus `index.html` and `latest.json`.
- The HTML table is client-side paginated (`REPORT_PAGE_SIZE`, 100 rows per page) and filters on cached text, so a report with thousands of package versions stays responsive in the browser.

## Configuration

`SCAN_INTERVAL_HOURS` (24), `SCAN_ON_START` (true), `OSV_ENABLED` (true), `OSV_BATCH_SIZE` (100), `OSV_TIMEOUT_SECONDS` (30), `OSV_RETRIES` (2), `MAX_TARBALL_MB` (2048), `REPORT_HTTP_BIND` (0.0.0.0), `REPORT_HTTP_PORT` (8080), `REPORT_TOKEN` (empty = open access), `LOG_LEVEL` (INFO).

## Important

- Storage layouts vary by Verdaccio version and storage plugin. This implementation recognizes packument JSON and package tarballs; validate the first scan counts against your registry.
- OSV reports known vulnerabilities, not malware detection or a guarantee of safety.
- If OSV is unreachable, inventory is still produced and the report shows the OSV error. Empty findings during an OSV error must not be interpreted as zero vulnerabilities.
- A locally calculated SHA-256 proves the scanned bytes' identity, not publisher identity, origin, signature, or provenance.
- The report JSON is a practical inventory schema, not formal CycloneDX/SPDX output.
- Versions present in metadata but without a local cached tarball remain listed, with no local SHA-256.
- The storage mount is read-only (`:ro`); scanner does not modify Verdaccio files.

## Operations

```bash
docker compose -f compose.yml ps
docker compose -f compose.yml logs --tail=200
ls -lh reports/
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/api/scan
curl -X POST http://127.0.0.1:8080/api/scan
```

Restart to trigger an immediate scan (startup scan is enabled):

```bash
docker compose -f compose.yml restart verdaccio-supply-chain
```
