"""
EDDMC - Network Blocker

Inserts an iptables rule to block outbound traffic from a suspicious PID,
scoped via the cgroup v2 path match (`-m cgroup --path`) rather than the
legacy net_cls classid mechanism -- net_cls is a cgroup v1 controller and
is not mounted on cgroup-v2-only systems (the common case today).

Strategy:
  1. Create/reuse a per-PID cgroup under CGROUP_ROOT (the throttler may
     have already created one) and move the process into it.
  2. Add an iptables OUTPUT rule matching that cgroup's path and DROP it.

There is deliberately no UID-based fallback: blocking by UID drops traffic
for every process owned by that user (or, if the target runs as root, every
root-owned process on the host) -- far broader than the single flagged PID.
If the cgroup-based block can't be applied, block() fails closed (logs and
returns False) rather than silently blocking something much bigger.
"""

import os
import subprocess
import logging

logger = logging.getLogger("eddmc.blocker")

CGROUP_ROOT = "/sys/fs/cgroup/eddmc"

_blocked_pids: set[int] = set()


def _cgroup_path(pid: int) -> str:
    return os.path.join(CGROUP_ROOT, str(pid))


def _cgroup_relpath(pid: int) -> str:
    """Path relative to the cgroup2 mount, as expected by `iptables -m cgroup --path`."""
    return f"eddmc/{pid}"


def _run(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Command failed %s: %s", cmd, e.stderr.decode())
        return False


def block(pid: int) -> bool:
    """
    Block all outbound network traffic from `pid`, scoped to that PID only.
    Returns True on success, False if the cgroup-based block could not be
    applied (in which case nothing is blocked -- fails closed).
    """
    if pid in _blocked_pids:
        return True

    cg = _cgroup_path(pid)
    try:
        os.makedirs(cg, exist_ok=True)
        # Move process into its cgroup (may already be done by throttler)
        with open(os.path.join(cg, "cgroup.procs"), "w") as f:
            f.write(str(pid))

        relpath = _cgroup_relpath(pid)
        ok = _run([
            "iptables", "-I", "OUTPUT", "1",
            "-m", "cgroup", "--path", relpath,
            "-j", "DROP",
            "-m", "comment", "--comment", f"eddmc-block-{pid}",
        ])

        if ok:
            _blocked_pids.add(pid)
            logger.warning("[BLOCK] pid=%d outbound traffic blocked (cgroup=%s)", pid, relpath)
        else:
            logger.error(
                "[BLOCK] pid=%d could not be scoped via cgroup v2 path match -- "
                "refusing to fall back to a broader (UID-based) block", pid,
            )
        return ok

    except (OSError, PermissionError) as exc:
        logger.error("Block failed for pid %d: %s", pid, exc)
        return False


def unblock(pid: int) -> bool:
    """Remove the iptables block for `pid`."""
    if pid not in _blocked_pids:
        return True
    relpath = _cgroup_relpath(pid)
    ok = _run([
        "iptables", "-D", "OUTPUT",
        "-m", "cgroup", "--path", relpath,
        "-j", "DROP",
        "-m", "comment", "--comment", f"eddmc-block-{pid}",
    ])
    if ok:
        _blocked_pids.discard(pid)
        logger.info("[UNBLOCK] pid=%d network rule removed", pid)
    return ok
