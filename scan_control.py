#!/usr/bin/env python3
"""Shared scan state and on-demand trigger; Python standard library only."""
import threading
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

    def end(self, summary=None, error=None, generated_at=None):
        with self._lock:
            self.phase = IDLE
            self.finished_at = now_iso()
            self.summary = summary
            self.generated_at = generated_at
            self.error = error

    def status(self):
        with self._lock:
            return {
                "phase": self.phase,
                "running": self.phase != IDLE,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "generated_at": self.generated_at,
                "last_error": self.error,
                "last_summary": self.summary,
                "runs_total": self.runs,
                "requests_total": self.requests,
                "requests_rejected": self.rejected,
            }


CONTROL = ScanControl()
