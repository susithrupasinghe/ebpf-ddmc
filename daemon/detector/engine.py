"""
EDDMC - Detection Engine

Runs on a periodic timer, iterates all tracked processes, extracts
features, scores them, and dispatches mitigation actions when thresholds
are crossed.  Emits structured detection events to the alerts bus.
"""

import threading
import time
import logging
from typing import Callable

from daemon.detector.features import extract
from daemon.detector.scorer   import score, ScoringResult

logger = logging.getLogger("eddmc.detector")


class DetectionEngine:
    """
    Periodically scans `process_store` and runs the scoring pipeline.
    Calls `on_detection(result)` for any process whose confidence > NONE.
    Calls `on_mitigation(result)` when mitigation action != NONE.
    """

    def __init__(
        self,
        process_store: dict,
        lock: threading.Lock,
        on_detection:  Callable[[ScoringResult], None],
        on_mitigation: Callable[[ScoringResult], None],
        interval_s: float = 5.0,
    ):
        self._store         = process_store
        self._lock          = lock
        self._on_detection  = on_detection
        self._on_mitigation = on_mitigation
        self._interval      = interval_s
        self._running       = False
        # Track which PIDs have already had mitigation applied
        self._mitigated: set[int] = set()

    def start(self):
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True, name="detection-engine")
        t.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            time.sleep(self._interval)
            self._scan()

    def _scan(self):
        with self._lock:
            snapshot = list(self._store.items())

        for pid, data in snapshot:
            try:
                features = extract(pid, data)
                result   = score(pid, data.get("comm", ""), features)

                # Update store with latest score
                with self._lock:
                    if pid in self._store:
                        self._store[pid]["score"]      = result.score
                        self._store[pid]["confidence"] = result.confidence
                        self._store[pid]["mitigation"] = result.mitigation

                if result.confidence != "NONE":
                    logger.info(
                        "[DETECT] pid=%d comm=%s score=%.1f confidence=%s",
                        pid, result.comm, result.score, result.confidence,
                    )
                    self._on_detection(result)

                if result.mitigation != "NONE" and pid not in self._mitigated:
                    self._mitigated.add(pid)
                    self._on_mitigation(result)

                # Re-enable mitigation re-evaluation if score dropped
                elif result.confidence == "NONE" and pid in self._mitigated:
                    self._mitigated.discard(pid)

            except Exception as exc:
                logger.debug("Scoring error for pid %d: %s", pid, exc)
