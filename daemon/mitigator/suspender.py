"""
EDDMC - Process Suspender

Sends SIGSTOP to freeze a confirmed cryptominer and SIGCONT to resume
it.  Used for CRITICAL confidence detections before deciding to terminate,
allowing an operator to inspect the process first.
"""

import os
import signal
import logging

logger = logging.getLogger("eddmc.suspender")


def suspend(pid: int) -> bool:
    """Send SIGSTOP to `pid`. Returns True on success."""
    try:
        os.kill(pid, signal.SIGSTOP)
        logger.warning("[SUSPEND] pid=%d frozen with SIGSTOP", pid)
        return True
    except ProcessLookupError:
        logger.debug("pid %d already exited before suspend", pid)
        return False
    except PermissionError:
        logger.error("Cannot SIGSTOP pid %d (permission denied)", pid)
        return False


def resume(pid: int) -> bool:
    """Send SIGCONT to `pid`. Returns True on success."""
    try:
        os.kill(pid, signal.SIGCONT)
        logger.info("[RESUME] pid=%d resumed with SIGCONT", pid)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        logger.error("Cannot SIGCONT pid %d (permission denied)", pid)
        return False
