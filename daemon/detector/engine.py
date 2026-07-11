"""
EDDMC - Detection Engine

Runs on a periodic timer, builds a BehaviouralFingerprint for each tracked
process, scores it, maintains a temporal profile (how many consecutive
scan windows the process has been suspicious), and dispatches mitigation.

Temporal logic
--------------
suspicious_ticks increments each scan window the process scores >= LOW.
It resets when the score drops back to NONE.  Mitigation escalates only
after sufficient sustained suspicion — this is the primary defence against
false positives from bursty legitimate workloads.
"""

import threading
import time
import logging
from typing import Callable

from daemon.detector.fingerprint import (
    BehaviouralFingerprint, TemporalProfile, build as build_fingerprint
)
from daemon.detector.scorer import score, ScoringResult

logger = logging.getLogger("eddmc.detector")

# Minimum score to increment suspicious_ticks
TICK_THRESHOLD = 20.0

# Confidence-tier ranking used only to decide whether a fingerprint-registry
# match should elevate a process (distinct from the mitigation-tier ranking
# further down, which is a different label set: NONE/ALERT/THROTTLE/BLOCK/TERMINATE)
CONFIDENCE_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class DetectionEngine:
    def __init__(
        self,
        process_store:  dict,
        lock:           threading.Lock,
        on_detection:   Callable[[ScoringResult], None],
        on_mitigation:  Callable[[ScoringResult], None],
        interval_s:     float = 5.0,
        fingerprint_matcher=None,
    ):
        self._store         = process_store
        self._lock          = lock
        self._on_detection  = on_detection
        self._on_mitigation = on_mitigation
        self._interval      = interval_s
        self._matcher       = fingerprint_matcher
        self._running       = False

        # pid → TemporalProfile (persistent across scans)
        self._temporal:  dict[int, TemporalProfile] = {}
        # pid → set of mitigation tiers already applied
        self._mitigated: dict[int, str] = {}

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
        now = time.time()

        with self._lock:
            snapshot = list(self._store.items())

        for pid, data in snapshot:
            try:
                # ── Temporal profile ───────────────────────────────────────
                if pid not in self._temporal:
                    self._temporal[pid] = TemporalProfile(first_seen=now)
                temp = self._temporal[pid]
                temp.age_seconds = now - temp.first_seen

                # ── Build fingerprint and score ────────────────────────────
                fp     = build_fingerprint(pid, data, temp)
                result = score(fp)

                # ── Fingerprint-registry acceleration ──────────────────────
                # A cosine-similarity match against a confirmed variant
                # elevates straight to HIGH, skipping the normal observation
                # window -- the detection-acceleration benefit of the registry.
                if (
                    self._matcher is not None
                    and CONFIDENCE_RANK.get(result.confidence, 0) < CONFIDENCE_RANK["HIGH"]
                ):
                    match = self._matcher.match(fp)
                    if match:
                        result.confidence = "HIGH"
                        result.mitigation = "BLOCK"
                        result.score = max(result.score, 60.0)
                        result.reasons.append(
                            f"fingerprint registry match: {match['process_name']} "
                            f"(similarity={match['similarity']:.2f}) — elevated without "
                            f"waiting for full observation window"
                        )

                # ── Update temporal state ──────────────────────────────────
                temp.score_history.append(result.score)
                if len(temp.score_history) > 12:   # keep last 60 seconds
                    temp.score_history = temp.score_history[-12:]

                if result.score >= TICK_THRESHOLD:
                    temp.suspicious_ticks += 1
                else:
                    temp.suspicious_ticks = 0   # reset on clean window

                if len(temp.score_history) >= 3:
                    mean = sum(temp.score_history) / len(temp.score_history)
                    variance = sum((x - mean) ** 2 for x in temp.score_history) / len(temp.score_history)
                    temp.score_variance = variance

                # ── Update store ───────────────────────────────────────────
                with self._lock:
                    if pid in self._store:
                        self._store[pid]["score"]      = result.score
                        self._store[pid]["confidence"] = result.confidence
                        self._store[pid]["mitigation"] = result.mitigation
                        self._store[pid]["reasons"]    = result.reasons
                        self._store[pid]["ticks"]      = temp.suspicious_ticks

                if result.confidence == "NONE":
                    self._mitigated.pop(pid, None)
                    continue

                # ── Emit detection event ───────────────────────────────────
                logger.info(
                    "[DETECT] pid=%d comm=%s score=%.1f conf=%s ticks=%d",
                    pid, result.comm, result.score,
                    result.confidence, temp.suspicious_ticks,
                )
                self._on_detection(result)

                # ── Dispatch mitigation (once per tier) ────────────────────
                prev_tier = self._mitigated.get(pid, "NONE")
                curr_tier = result.mitigation
                tier_rank = {"NONE": 0, "ALERT": 1, "THROTTLE": 2, "BLOCK": 3, "TERMINATE": 4}

                if tier_rank.get(curr_tier, 0) > tier_rank.get(prev_tier, 0):
                    self._mitigated[pid] = curr_tier
                    self._on_mitigation(result)

            except Exception as exc:
                logger.debug("Scoring error for pid %d: %s", pid, exc)

        # ── GC temporal state for dead processes ───────────────────────────
        live_pids = set(pid for pid, _ in snapshot)
        for pid in list(self._temporal.keys()):
            if pid not in live_pids:
                del self._temporal[pid]
                self._mitigated.pop(pid, None)
