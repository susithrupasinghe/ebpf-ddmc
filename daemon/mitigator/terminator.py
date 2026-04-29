"""
EDDMC - Process Terminator

Sends SIGKILL to terminate a confirmed cryptominer.  This is the
last step in the mitigation cascade and is only triggered when:
  - confidence is CRITICAL (score >= 80), AND
  - the operator policy allows auto-terminate (config: auto_kill=true)

A SIGTERM is attempted first with a short grace period; SIGKILL follows
if the process has not exited.
"""

import os
import signal
import time
import logging

logger = logging.getLogger("eddmc.terminator")

SIGTERM_GRACE_S = 3.0   # seconds to wait between SIGTERM and SIGKILL


def terminate(pid: int, grace: float = SIGTERM_GRACE_S) -> bool:
    """
    Terminates `pid` gracefully (SIGTERM then SIGKILL).
    Returns True if the process was successfully killed.
    """
    try:
        logger.warning("[TERMINATE] pid=%d sending SIGTERM", pid)
        os.kill(pid, signal.SIGTERM)
        time.sleep(grace)
        # Check if still running
        os.kill(pid, 0)   # raises ProcessLookupError if dead
        # Still alive — escalate
        logger.warning("[TERMINATE] pid=%d did not exit, sending SIGKILL", pid)
        os.kill(pid, signal.SIGKILL)
        logger.warning("[TERMINATE] pid=%d killed", pid)
        return True
    except ProcessLookupError:
        logger.info("[TERMINATE] pid=%d exited after SIGTERM", pid)
        return True
    except PermissionError:
        logger.error("Cannot terminate pid %d (permission denied)", pid)
        return False
