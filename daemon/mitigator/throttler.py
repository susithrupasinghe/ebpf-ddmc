"""
EDDMC - CPU Throttler

Limits a process's CPU quota using Linux cgroups v2.
Creates a cgroup under /sys/fs/cgroup/eddmc/<pid>/ and moves the
process into it, then sets cpu.max to restrict its share.

Throttle level is set relative to the detection confidence:
  MEDIUM   → 30% CPU
  HIGH     → 10% CPU
  CRITICAL →  5% CPU (before further action)
"""

import os
import logging

logger = logging.getLogger("eddmc.throttler")

CGROUP_ROOT = "/sys/fs/cgroup/eddmc"
PERIOD_US   = 100_000   # 100 ms period


def _cgroup_path(pid: int) -> str:
    return os.path.join(CGROUP_ROOT, str(pid))


def _ensure_root():
    os.makedirs(CGROUP_ROOT, exist_ok=True)


def throttle(pid: int, confidence: str) -> bool:
    """
    Move `pid` into a cgroup and apply a CPU quota.
    Returns True on success, False if the process no longer exists or
    cgroups are not available.
    """
    quota_pct = {"MEDIUM": 30, "HIGH": 10, "CRITICAL": 5}.get(confidence, 30)
    quota_us  = int(PERIOD_US * quota_pct / 100)

    try:
        _ensure_root()
        cg = _cgroup_path(pid)
        os.makedirs(cg, exist_ok=True)

        # Move process into cgroup
        with open(os.path.join(cg, "cgroup.procs"), "w") as f:
            f.write(str(pid))

        # Apply CPU quota: "quota period" format
        with open(os.path.join(cg, "cpu.max"), "w") as f:
            f.write(f"{quota_us} {PERIOD_US}")

        logger.warning(
            "[THROTTLE] pid=%d confidence=%s quota=%d%% (%d/%d µs)",
            pid, confidence, quota_pct, quota_us, PERIOD_US,
        )
        return True

    except FileNotFoundError:
        logger.debug("pid %d exited before throttle could be applied", pid)
        return False
    except PermissionError:
        logger.error("Cannot write to cgroup (not root?)")
        return False
    except Exception as exc:
        logger.error("Throttle failed for pid %d: %s", pid, exc)
        return False


def unthrottle(pid: int):
    """Remove the process from its throttle cgroup and clean up."""
    cg = _cgroup_path(pid)
    try:
        # Move back to root cgroup
        with open(os.path.join(CGROUP_ROOT, "cgroup.procs"), "w") as f:
            f.write(str(pid))
        # Reset quota to unlimited
        with open(os.path.join(cg, "cpu.max"), "w") as f:
            f.write(f"max {PERIOD_US}")
        os.rmdir(cg)
        logger.info("[UNTHROTTLE] pid=%d released from cgroup", pid)
    except Exception as exc:
        logger.debug("Unthrottle cleanup for pid %d: %s", pid, exc)
