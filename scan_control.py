#!/usr/bin/env python3
"""Shared scan state and on-demand trigger; Python standard library only."""
import threading, time
from datetime import datetime, timezone

IDLE = "idle"
REQUESTED = "requested"
RUNNING = "running"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


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


CONTROL = ScanControl()
