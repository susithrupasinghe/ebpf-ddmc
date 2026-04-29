"""
EDDMC - Network Blocker

Inserts iptables rules to block outbound traffic from a suspicious PID
using the owner match module (--uid-owner blocks by UID, which is
imprecise; we prefer --pid-owner via the cgroup net_cls controller for
exact PID-level blocking).

Strategy:
  1. Write net_cls classid into the process's cgroup so the kernel
     tags all its packets with a unique class.
  2. Add an iptables OUTPUT rule that drops traffic with that classid.

Falls back to UID-based blocking if net_cls is unavailable.
"""

import os
import subprocess
import logging

logger = logging.getLogger("eddmc.blocker")

CGROUP_ROOT  = "/sys/fs/cgroup/eddmc"
CLASSID_BASE = 0x00100001   # arbitrary; incremented per blocked PID

_blocked_pids: dict[int, int] = {}   # pid → classid


def _cgroup_path(pid: int) -> str:
    return os.path.join(CGROUP_ROOT, str(pid))


def _run(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Command failed %s: %s", cmd, e.stderr.decode())
        return False


def block(pid: int) -> bool:
    """
    Block all outbound network traffic from `pid`.
    Returns True on success.
    """
    if pid in _blocked_pids:
        return True

    classid = CLASSID_BASE + len(_blocked_pids)
    _blocked_pids[pid] = classid

    cg = _cgroup_path(pid)
    try:
        os.makedirs(cg, exist_ok=True)
        # Move process to its cgroup (may already be done by throttler)
        with open(os.path.join(cg, "cgroup.procs"), "w") as f:
            f.write(str(pid))

        # Set net_cls classid for packet tagging
        net_cls_file = os.path.join(cg, "net_cls.classid")
        if os.path.exists(net_cls_file):
            with open(net_cls_file, "w") as f:
                f.write(str(classid))

            # iptables rule matching the classid
            major = (classid >> 16) & 0xFFFF
            minor = classid & 0xFFFF
            ok = _run([
                "iptables", "-I", "OUTPUT", "1",
                "-m", "cgroup", "--cgroup", f"{major}:{minor}",
                "-j", "DROP",
                "-m", "comment", "--comment", f"eddmc-block-{pid}",
            ])
        else:
            # Fallback: block by UID (less precise)
            try:
                import psutil
                proc = psutil.Process(pid)
                uid  = proc.uids().real
            except Exception:
                uid = 0
            ok = _run([
                "iptables", "-I", "OUTPUT", "1",
                "-m", "owner", "--uid-owner", str(uid),
                "-j", "DROP",
                "-m", "comment", "--comment", f"eddmc-block-uid-{uid}",
            ])

        if ok:
            logger.warning("[BLOCK] pid=%d outbound traffic blocked (classid=%s)",
                           pid, hex(classid))
        return ok

    except Exception as exc:
        logger.error("Block failed for pid %d: %s", pid, exc)
        return False


def unblock(pid: int) -> bool:
    """Remove the iptables block for `pid`."""
    if pid not in _blocked_pids:
        return True
    classid = _blocked_pids.pop(pid)
    major   = (classid >> 16) & 0xFFFF
    minor   = classid & 0xFFFF
    ok = _run([
        "iptables", "-D", "OUTPUT",
        "-m", "cgroup", "--cgroup", f"{major}:{minor}",
        "-j", "DROP",
        "-m", "comment", "--comment", f"eddmc-block-{pid}",
    ])
    if ok:
        logger.info("[UNBLOCK] pid=%d network rule removed", pid)
    return ok
