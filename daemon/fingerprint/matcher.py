"""
EDDMC - Fingerprint Matcher

Downloads confirmed fingerprints from the registry at startup and every
`refresh_interval_hours`, then checks each newly-observed process against
the confirmed set using cosine similarity. A match above `threshold`
(default 0.85) lets the detection engine elevate the process straight to
HIGH confidence without waiting for the normal temporal-gated scoring
cycle -- the primary detection-acceleration benefit of the registry.
"""

from __future__ import annotations

import json
import logging
import math
import threading
import time
import urllib.error
import urllib.request
from typing import Optional

from daemon.detector.fingerprint import BehaviouralFingerprint
from daemon.fingerprint.packager import feature_vector

logger = logging.getLogger("eddmc.fingerprint.matcher")


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


class FingerprintMatcher:
    def __init__(
        self,
        registry_url: str,
        threshold: float = 0.85,
        refresh_interval_hours: float = 1.0,
        timeout: float = 5.0,
    ):
        self._url = registry_url.rstrip("/") + "/api/v1/fingerprints"
        self._threshold = threshold
        self._interval = max(refresh_interval_hours, 0.01) * 3600
        self._timeout = timeout
        self._lock = threading.Lock()
        self._confirmed: list[dict] = []
        self._running = False

    def start(self):
        self._running = True
        self.refresh()
        t = threading.Thread(target=self._loop, daemon=True, name="fingerprint-matcher")
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
                self._confirmed = data
            logger.info("Fingerprint registry refreshed: %d confirmed entries", len(data))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            logger.debug("Fingerprint registry unreachable: %s", exc)

    def match(self, fp: BehaviouralFingerprint) -> Optional[dict]:
        vector = feature_vector(fp)
        with self._lock:
            confirmed = list(self._confirmed)

        best = None
        for entry in confirmed:
            sim = _cosine(vector, entry.get("feature_vector", []))
            if sim >= self._threshold and (best is None or sim > best["similarity"]):
                best = {
                    "similarity": round(sim, 4),
                    "fingerprint_id": entry.get("fingerprint_id"),
                    "process_name": entry.get("process_name"),
                }
        return best
