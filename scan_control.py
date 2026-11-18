#!/usr/bin/env python3
"""Shared scan state and on-demand trigger; Python standard library only."""
import os, socket, threading, time
from datetime import datetime, timezone
from pathlib import Path

IDLE = "idle"
REQUESTED = "requested"
RUNNING = "running"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class ScanLock:
    """Detect a second scanner working on the same report directory."""

    def __init__(self, path, stale_seconds):
        self.path = Path(path)
        self.stale = max(30, int(stale_seconds))
        self.host = socket.gethostname()

    def _owner(self):
        try:
            text = self.path.read_text(encoding="utf-8").strip()
        except OSError:
            return None, None
        parts = dict(p.split("=", 1) for p in text.split() if "=" in p)
        return parts.get("pid"), parts.get("host")

    def held_by_other(self):
        """True when another host/container refreshed the lock recently."""
        try:
            if not self.path.exists():
                return False
            pid, host = self._owner()
            if host == self.host:
                return False
            return (time.time() - self.path.stat().st_mtime) < self.stale
        except OSError:
            return False

    def owner_alive(self, wait=3):
        """True when the lock file keeps being refreshed by a live scanner."""
        try:
            before = self.path.stat().st_mtime
        except OSError:
            return False
        time.sleep(wait)
        try:
            return self.path.stat().st_mtime > before
        except OSError:
            return False

    def claim(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(f"pid={os.getpid()} host={self.host} started={now_iso()}\n",
                                 encoding="utf-8")
        except OSError:
            pass

    def heartbeat(self):
        try:
            self.path.touch()
        except OSError:
            pass


class ScanControl:
    """State machine shared by the scanner loop and the HTTP API.

    phase: idle -> requested -> running -> idle
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.trigger = threading.Event()
        self.phase = IDLE
        self.started_at = None
        self.finished_at = None
        self.generated_at = None
        self.error = None
        self.summary = None
        self.runs = 0
        self.requests = 0
        self.rejected = 0
        self.progress = {"phase": "idle", "current": 0, "total": 0, "percent": None,
                         "message": "", "updated_at": None}
        self._started_clock = None
        self._finished_clock = None

    def request(self):
        """Reserve the scan slot. Returns (accepted, detail)."""
        with self._lock:
            if self.phase != IDLE:
                self.rejected += 1
                return False, "a scan is already running"
            self.phase = REQUESTED
            self.requests += 1
            self.trigger.set()
            return True, "scan scheduled"

    def begin(self):
        with self._lock:
            self.phase = RUNNING
            self.started_at = now_iso()
            self.finished_at = None
            self.generated_at = None
            self.error = None
            self.summary = None
            self.runs += 1
            self._started_clock = time.monotonic()
            self._finished_clock = None
            self.progress = {"phase": "starting", "current": 0, "total": 0, "percent": None,
                             "message": "scan started", "updated_at": now_iso()}

    def set_progress(self, phase, current=None, total=None, message=""):
        with self._lock:
            percent = None
            if total:
                percent = round(min(current or 0, total) * 100.0 / total, 1)
            self.progress = {"phase": phase, "current": current, "total": total,
                             "percent": percent, "message": message, "updated_at": now_iso()}

    def end(self, summary=None, error=None, generated_at=None):
        with self._lock:
            self.phase = IDLE
            self.finished_at = now_iso()
            self.summary = summary
            self.generated_at = generated_at
            self.error = error
            self._finished_clock = time.monotonic()
            self.progress = dict(self.progress, phase="completed" if not error else "failed",
                                 message="scan finished" if not error else str(error)[:200],
                                 updated_at=now_iso())

    def status(self):
        with self._lock:
            elapsed = None
            if self._started_clock is not None:
                end_clock = self._finished_clock if self._finished_clock is not None else time.monotonic()
                elapsed = round(end_clock - self._started_clock, 1)
            return {
                "phase": self.phase,
                "running": self.phase != IDLE,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "generated_at": self.generated_at,
                "elapsed_seconds": elapsed,
                "last_error": self.error,
                "last_summary": self.summary,
                "progress": dict(self.progress),
                "runs_total": self.runs,
                "requests_total": self.requests,
                "requests_rejected": self.rejected,
            }


class ReportStore:
    """Keep the latest report in memory so the portal can page through it."""

    def __init__(self):
        self._lock = threading.Lock()
        self.report = None

    def set(self, report):
        with self._lock:
            self.report = report

    def get(self):
        with self._lock:
            return self.report


REPORTS = ReportStore()
CONTROL = ScanControl()
LOCK = ScanLock(os.getenv("REPORT_DIR", "/reports") + "/.scan.lock",
                os.getenv("SCAN_LOCK_STALE_SECONDS", "180"))
