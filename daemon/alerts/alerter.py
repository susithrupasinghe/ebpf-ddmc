"""
EDDMC - Alert Bus

Collects structured detection/mitigation events and writes them to
a rotating JSONL log file.  The IPC server (Unix socket) handles
real-time delivery to the Electron UI and CLI.
"""

import json
import logging
import os
import queue
import threading

logger = logging.getLogger("eddmc.alerter")

DEFAULT_LOG = "/var/log/eddmc/alerts.jsonl"


class AlertBus:
    def __init__(self, log_path: str = DEFAULT_LOG, **_kwargs):
        self._q        = queue.Queue()
        self._log_path = log_path
        self._running  = False

    def push(self, alert: dict):
        self._q.put(alert)

    def start(self):
        self._running = True
        threading.Thread(target=self._drain, daemon=True, name="alert-bus").start()

    def stop(self):
        self._running = False

    def _drain(self):
        os.makedirs(os.path.dirname(self._log_path), exist_ok=True)
        while self._running:
            try:
                alert = self._q.get(timeout=1.0)
                try:
                    with open(self._log_path, "a") as f:
                        f.write(json.dumps(alert) + "\n")
                except OSError as e:
                    logger.debug("Alert log write error: %s", e)
            except queue.Empty:
                continue
