"""
EDDMC - Fingerprint Confirmation Gate

Before any behavioural fingerprint is packaged and submitted to the
Distributed Behavioural Fingerprint Registry, it must pass four
simultaneous conditions. The gate prioritises precision over recall --
a missed submission is preferable to a false-positive fingerprint that
could poison every other deployment's matcher:

  1. Sustained CRITICAL score for >= `sustained_critical_seconds` (60s default)
  2. At least one confirmed stratum pool connection (pool_hits > 0)
  3. futex_ratio, cpu_bound_ratio and thread_density all simultaneously
     exceed their "strong" detection thresholds
  4. The process binary is hashed via /proc/<pid>/exe (best effort --
     absence of a hash does not block submission)
"""

from __future__ import annotations

import time
from typing import Optional

from daemon.detector.scorer import ScoringResult
from daemon.fingerprint.packager import binary_hash

STRONG_FUTEX_RATIO = 0.40
STRONG_CPU_BOUND_RATIO = 0.92
STRONG_THREAD_DENSITY = 1.0


class FingerprintAssessor:
    def __init__(self, sustained_critical_seconds: float = 60.0):
        self._sustained_s = sustained_critical_seconds
        self._critical_since: dict[int, float] = {}

    def evaluate(self, result: ScoringResult, now: Optional[float] = None) -> Optional[dict]:
        """Called once per scan tick for every scored process. Returns an
        evidence dict the moment all four gate conditions pass, else None.
        `now` is injectable for testing without real sleeps."""
        now = now if now is not None else time.time()
        pid = result.pid

        if result.confidence != "CRITICAL":
            self._critical_since.pop(pid, None)
            return None

        if pid not in self._critical_since:
            self._critical_since[pid] = now
        sustained = now - self._critical_since[pid]

        fp = result.fingerprint
        sc, sch, par, net = fp.syscall, fp.scheduler, fp.parallelism, fp.network

        cond_sustained = sustained >= self._sustained_s
        cond_pool = net.pool_connections > 0
        cond_features = (
            sc.futex_ratio >= STRONG_FUTEX_RATIO
            and sch.cpu_bound_ratio >= STRONG_CPU_BOUND_RATIO
            and par.thread_cpu_ratio >= STRONG_THREAD_DENSITY
        )

        if not (cond_sustained and cond_pool and cond_features):
            return None

        return {
            "score": result.score,
            "sustained_seconds": round(sustained, 1),
            "binary_sha256": binary_hash(pid),
        }

    def forget(self, pid: int):
        self._critical_since.pop(pid, None)
