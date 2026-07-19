"""
EDDMC - Registry-backed Allowlist Sync

Downloads the registry's CONFIRMED known-good binary hashes at startup and
every `refresh_interval_hours`, mirroring FingerprintMatcher's download/
refresh pattern -- but membership here is exact hash-set lookup, not cosine
similarity, since a binary either is or isn't the trusted one.

Only status='confirmed' entries are ever returned by the registry's
GET /api/v1/allowlist -- that channel has no auto-confirm mode at all (see
registry/app.py), so every hash synced here was explicitly reviewed by an
administrator, not just self-reported by a node.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request

logger = logging.getLogger("eddmc.fingerprint.allowlist_sync")


class AllowlistSync:
    def __init__(
        self,
        registry_url: str,
        refresh_interval_hours: float = 1.0,
        timeout: float = 5.0,
    ):
        self._url = registry_url.rstrip("/") + "/api/v1/allowlist"
        self._interval = max(refresh_interval_hours, 0.01) * 3600
        self._timeout = timeout
        self._lock = threading.Lock()
        self._confirmed: dict[str, str] = {}   # sha256 -> description
        self._running = False

    def start(self):
        self._running = True
        self.refresh()
        t = threading.Thread(target=self._loop, daemon=True, name="allowlist-sync")
        t.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            time.sleep(self._interval)
            self.refresh()

    def refresh(self):
        try:
            with urllib.request.urlopen(self._url, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
            with self._lock:
                self._confirmed = {e["sha256"]: e.get("description", "") for e in data}
            logger.info("Registry allowlist refreshed: %d confirmed entries", len(self._confirmed))
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as exc:
            logger.debug("Allowlist registry unreachable: %s", exc)

    def hashes(self) -> set[str]:
        with self._lock:
            return set(self._confirmed.keys())
