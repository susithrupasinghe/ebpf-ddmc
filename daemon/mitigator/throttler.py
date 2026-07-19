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

CGROUP_ROOT   = "/sys/fs/cgroup/eddmc"
CGROUP_MOUNT  = "/sys/fs/cgroup"
PERIOD_US     = 100_000   # 100 ms period

_cpu_delegated = False

# pid -> its cgroup v2 path (relative to CGROUP_MOUNT) at the moment we
# throttled it, so unthrottle() can put it back where it came from.
_original_cgroup: dict[int, str] = {}


def _cgroup_path(pid: int) -> str:
    return os.path.join(CGROUP_ROOT, str(pid))


def _current_cgroup_relpath(pid: int) -> str | None:
    """Read /proc/<pid>/cgroup and return its cgroup v2 path, relative to CGROUP_MOUNT."""
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            for line in f:
                # cgroup v2 unified hierarchy: "0::/path/to/cgroup"
                if line.startswith("0::"):
                    return line.strip()[3:].lstrip("/")
    except OSError:
        pass
    return None


def _delegate_cpu_controller():
    """
    Enable the "cpu" controller on CGROUP_ROOT's subtree_control so its
    children (the per-PID leaf cgroups) actually get a cpu.max interface
    file. Without this, cgroup v2 never creates cpu.max for children, and
    writing to that nonexistent path is rejected with EACCES/PermissionError
    -- nothing to do with the daemon's own root privileges, despite how that
    error looks.
    """
    global _cpu_delegated
    if _cpu_delegated:
        return
    control_file = os.path.join(CGROUP_ROOT, "cgroup.subtree_control")
    try:
        with open(control_file, "r") as f:
            enabled = f.read().split()
        if "cpu" not in enabled:
            with open(control_file, "w") as f:
                f.write("+cpu")
        _cpu_delegated = True
    except OSError as exc:
        logger.error("Could not delegate cpu controller to %s: %s", CGROUP_ROOT, exc)


def _ensure_root():
    os.makedirs(CGROUP_ROOT, exist_ok=True)
    _delegate_cpu_controller()


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

        # Remember where this pid actually lives before moving it, so
        # unthrottle() can put it back -- not just at THROTTLE but also on a
        # later re-throttle() when escalating to BLOCK/TERMINATE, which must
        # not clobber the true original with our own cgroup path.
        if pid not in _original_cgroup:
            relpath = _current_cgroup_relpath(pid)
            if relpath is not None:
                _original_cgroup[pid] = relpath

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
    """
    Remove the process from its throttle cgroup and clean up.
    If `pid` already exited, the kernel has already dropped it from the
    cgroup, so the move-back write below fails harmlessly and rmdir alone
    cleans up. If it's still alive but can't be relocated (unknown original
    cgroup, or blocked by the "no internal process constraint" -- see
    _delegate_cpu_controller), fall back to lifting the CPU cap in place
    rather than leaving it stuck throttled with no way out.
    """
    cg = _cgroup_path(pid)
    moved = False
    try:
        relpath = _original_cgroup.get(pid)
        dest = os.path.join(CGROUP_MOUNT, relpath) if relpath else CGROUP_ROOT
        with open(os.path.join(dest, "cgroup.procs"), "w") as f:
            f.write(str(pid))
        moved = True
    except OSError:
        pass
    finally:
        _original_cgroup.pop(pid, None)

    if not moved:
        try:
            with open(os.path.join(cg, "cpu.max"), "w") as f:
                f.write(f"max {PERIOD_US}")
        except OSError:
            pass

    try:
        os.rmdir(cg)
        logger.info("[UNTHROTTLE] pid=%d released from cgroup", pid)
    except OSError as exc:
        logger.debug("Unthrottle cleanup for pid %d: %s", pid, exc)
