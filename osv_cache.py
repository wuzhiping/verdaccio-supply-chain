#!/usr/bin/env python3
"""Persistent cache for OSV lookups; standard library only (sqlite3)."""
import os, json, time, sqlite3, threading, logging

log = logging.getLogger("supply-chain.cache")

SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    ecosystem TEXT NOT NULL,
    name      TEXT NOT NULL,
    version   TEXT NOT NULL,
    vulns     TEXT NOT NULL,
    fetched   REAL NOT NULL,
    PRIMARY KEY (ecosystem, name, version)
);
CREATE TABLE IF NOT EXISTS advisories (
    id      TEXT PRIMARY KEY,
    record  TEXT NOT NULL,
    fetched REAL NOT NULL
);
"""


class OsvCache:
    """Cache of OSV query results and advisory details, stored next to the reports."""

    def __init__(self, directory, ttl_days=7, enabled=True):
        self.enabled = enabled
        self.ttl = max(0, int(ttl_days)) * 86400
        self.path = os.path.join(directory, "osv-cache.db") if directory else None
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self._conn = None
        if not enabled or not self.path:
            log.info("OSV cache disabled")
            return
        try:
            os.makedirs(directory, exist_ok=True)
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.executescript(SCHEMA)
            self._conn.commit()
            log.info("OSV cache ready: %s", self.path)
        except Exception as e:
            log.warning("Cannot open the OSV cache (%s), continuing without it", e)
            self._conn = None

    def _fresh(self, fetched):
        return self.ttl <= 0 or (time.time() - fetched) < self.ttl

    def get_queries(self, ecosystem, name, version):
        """Cached vulnerability list of one package version."""
        if not self._conn:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT vulns, fetched FROM queries WHERE ecosystem=? AND name=? AND version=?",
                (ecosystem, name, version)).fetchone()
        if not row:
            self.misses += 1
            return None
        if not self._fresh(row[1]):
            self.misses += 1
            return None
        self.hits += 1
        try:
            return json.loads(row[0])
        except ValueError:
            return None

    def set_queries(self, ecosystem, name, version, vulns):
        if not self._conn:
            return
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO queries (ecosystem, name, version, vulns, fetched) VALUES (?,?,?,?,?)",
                    (ecosystem, name, version, json.dumps(vulns, ensure_ascii=False), time.time()))
                self._conn.commit()
        except Exception as e:
            log.debug("Cannot write the OSV query cache: %s", e)

    def get_advisory(self, vid):
        """Cached detail record of one advisory."""
        if not self._conn:
            return None
        with self._lock:
            row = self._conn.execute("SELECT record, fetched FROM advisories WHERE id=?", (vid,)).fetchone()
        if not row:
            self.misses += 1
            return None
        if not self._fresh(row[1]):
            self.misses += 1
            return None
        self.hits += 1
        try:
            return json.loads(row[0])
        except ValueError:
            return None

    def set_advisory(self, vid, record):
        if not self._conn:
            return
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO advisories (id, record, fetched) VALUES (?,?,?)",
                    (vid, json.dumps(record, ensure_ascii=False), time.time()))
                self._conn.commit()
        except Exception as e:
            log.debug("Cannot write the OSV advisory cache: %s", e)

    def stats(self):
        info = {"enabled": bool(self._conn), "hits": self.hits, "misses": self.misses,
                "path": self.path if self._conn else None, "queries": 0, "advisories": 0}
        if self._conn:
            try:
                with self._lock:
                    info["queries"] = self._conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
                    info["advisories"] = self._conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
            except Exception:
                pass
        return info


_INSTANCE = None


def get_cache(directory=None, ttl_days=None, enabled=None):
    """Shared cache instance, the scanner and the severity resolver use the same file."""
    global _INSTANCE
    if _INSTANCE is None:
        if directory is None:
            directory = os.getenv("OSV_CACHE_DIR", "") or os.path.join(
                os.getenv("REPORT_DIR", "/reports"), ".osv-cache")
        if ttl_days is None:
            ttl_days = int(os.getenv("OSV_CACHE_TTL_DAYS", "7"))
        if enabled is None:
            enabled = os.getenv("OSV_CACHE", "true").lower() not in ("0", "false", "no")
        _INSTANCE = OsvCache(directory, ttl_days=ttl_days, enabled=enabled)
    return _INSTANCE
