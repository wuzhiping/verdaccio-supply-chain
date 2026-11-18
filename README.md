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

The scanner runs a full scan on startup, then every 24 hours. Open `reports/index.html` on the host. The service intentionally exposes no HTTP port; serve the reports directory through an existing authenticated Nginx if remote access is needed.

## What it does

- Recursively discovers packument-style JSON with a `versions` object.
- Scans `.tgz` tarballs and reads `package/package.json`.
- Computes SHA-256 for identified local tarballs.
- Records dependencies, optional/peer dependencies, and license metadata.
- Queries OSV for each package/version using ecosystem `npm`.
- Writes timestamped HTML/JSON plus `index.html` and `latest.json`.

## Configuration

`SCAN_INTERVAL_HOURS` (24), `SCAN_ON_START` (true), `OSV_ENABLED` (true), `OSV_BATCH_SIZE` (100), `OSV_TIMEOUT_SECONDS` (30), `OSV_RETRIES` (2), `MAX_TARBALL_MB` (2048), `LOG_LEVEL` (INFO).

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
```

Restart to trigger an immediate scan (startup scan is enabled):

```bash
docker compose -f compose.yml restart verdaccio-supply-chain
```
