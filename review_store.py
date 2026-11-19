#!/usr/bin/env python3
"""Reviewed findings, shared between the portal and the scanner; standard library only."""
import os, json, time, threading

KEYS = "reviewed.json"


class ReviewStore:
    """Marks findings as reviewed so they leave the statistics and the alerts."""

    def __init__(self, directory):
        self.path = os.path.join(directory, KEYS)
        self._lock = threading.Lock()
        self._keys = None
        self._mtime = None

    def _load(self):
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            self._keys, self._mtime = set(), None
            return self._keys
        if self._mtime == mtime and self._keys is not None:
            return self._keys
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            keys = set(data.get("reviewed") or [])
        except Exception:
            keys = set()
        self._keys, self._mtime = keys, mtime
        return keys

    def keys(self):
        with self._lock:
            return set(self._load())

    def reviewed(self, key):
        return key in self.keys()

    def set(self, key, reviewed=True):
        with self._lock:
            keys = self._load()
            if reviewed:
                keys.add(key)
            else:
                keys.discard(key)
            self._keys = keys
            directory = os.path.dirname(self.path)
            try:
                os.makedirs(directory, exist_ok=True)
                tmp = self.path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump({"reviewed": sorted(keys), "updated_at": time.time()}, fh, indent=1)
                os.replace(tmp, self.path)
                self._mtime = os.path.getmtime(self.path)
            except OSError:
                pass
            return key in keys


def finding_key(ecosystem, name, version, advisory):
    """Stable key of one finding."""
    return f"{ecosystem}:{name}@{version}:{advisory}"
