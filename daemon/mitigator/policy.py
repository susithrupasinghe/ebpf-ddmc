"""
EDDMC - Mitigation Policy Engine

Maps a ScoringResult to a sequence of mitigation actions based on
the configured policy.  This is the single entry point for all
mitigation decisions — nothing else calls throttler/blocker/etc directly.

Mitigation cascade (each level includes all levels below it):
  ALERT     → log + push alert to UI
  THROTTLE  → alert + cgroup CPU quota
  BLOCK     → throttle + iptables network block
  TERMINATE → block + SIGSTOP + SIGKILL (if auto_kill enabled)
"""

import logging
import time
from typing import Callable

from daemon.detector.scorer  import ScoringResult
from daemon.mitigator        import throttler, blocker, suspender, terminator

logger = logging.getLogger("eddmc.policy")


class MitigationPolicy:
    """
    Evaluates a ScoringResult and applies the appropriate mitigation.
    `alert_cb` is called with a structured alert dict for every action taken.
    """

    def __init__(
        self,
        alert_cb:    Callable[[dict], None],
        auto_kill:   bool  = False,
        dry_run:     bool  = False,
    ):
        self._alert_cb  = alert_cb
        self._auto_kill = auto_kill
        self._dry_run   = dry_run
        self._applied:  set[int] = set()

    def apply(self, result: ScoringResult):
        pid        = result.pid
        confidence = result.confidence
        action     = result.mitigation

        if action == "NONE":
            return

        alert = {
            "pid":        pid,
            "comm":       result.comm,
            "score":      result.score,
            "confidence": confidence,
            "action":     action,
            "reasons":    result.reasons,
            "features":   result.features,
            "timestamp":  time.time(),
        }

        if self._dry_run:
            logger.info("[DRY-RUN] Would apply %s to pid=%d (score=%.1f)",
                        action, pid, result.score)
            self._alert_cb({**alert, "dry_run": True})
            return

        # Always alert
        self._alert_cb(alert)
        logger.warning(
            "[MITIGATE] pid=%d comm=%s action=%s score=%.1f confidence=%s",
            pid, result.comm, action, result.score, confidence,
        )

        # Throttle for MEDIUM and above
        if action in ("THROTTLE", "BLOCK", "TERMINATE"):
            throttler.throttle(pid, confidence)

        # Network block for HIGH and above
        if action in ("BLOCK", "TERMINATE"):
            blocker.block(pid)

        # Suspend + terminate for CRITICAL
        if action == "TERMINATE":
            suspender.suspend(pid)
            if self._auto_kill:
                terminator.terminate(pid)
            else:
                logger.warning(
                    "[POLICY] pid=%d suspended but auto_kill=False — "
                    "operator intervention required", pid
                )

        self._applied.add(pid)

    def revoke(self, pid: int):
        """Undo mitigations if a process is later deemed benign."""
        if pid not in self._applied:
            return
        throttler.unthrottle(pid)
        blocker.unblock(pid)
        suspender.resume(pid)
        self._applied.discard(pid)
        logger.info("[REVOKE] pid=%d mitigations lifted", pid)
