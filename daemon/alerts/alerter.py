"""
EDDMC - Alert Bus

Collects structured detection/mitigation events and distributes them to:
  1. The rotating JSON log file  (alerts.jsonl)
  2. The Unix-socket IPC server  (consumed by CLI and Electron UI)
  3. syslog                      (optional, for SIEM integration)
"""

import json
import logging
import os
import queue
import socket
import threading
import time

logger = logging.getLogger("eddmc.alerter")

ALERT_LOG = "/var/log/eddmc/alerts.jsonl"


class AlertBus:
    """
    Thread-safe alert distributor.  Call `push(alert_dict)` from any thread;
    the bus drains the queue asynchronously and fans out to all subscribers.
    """

    def __init__(self, socket_path: str, log_path: str = ALERT_LOG):
        self._q           = queue.Queue()
        self._socket_path = socket_path
        self._log_path    = log_path
        self._clients:    list[socket.socket] = []
        self._client_lock = threading.Lock()
        self._running     = False

    def push(self, alert: dict):
        """Non-blocking enqueue of an alert."""
        self._q.put(alert)

    def start(self):
        self._running = True
        threading.Thread(target=self._drain, daemon=True, name="alert-bus").start()
        threading.Thread(target=self._listen, daemon=True, name="alert-ipc").start()

    def stop(self):
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────────────

    def _drain(self):
        os.makedirs(os.path.dirname(self._log_path), exist_ok=True)
        while self._running:
            try:
                alert = self._q.get(timeout=1.0)
                line  = json.dumps(alert) + "\n"
                # Write to file
                try:
                    with open(self._log_path, "a") as f:
                        f.write(line)
                except OSError as e:
                    logger.debug("Alert log write error: %s", e)
                # Fan-out to connected IPC clients
                self._broadcast(line.encode())
            except queue.Empty:
                continue

    def _broadcast(self, data: bytes):
        dead = []
        with self._client_lock:
            for c in self._clients:
                try:
                    c.sendall(data)
                except OSError:
                    dead.append(c)
            for c in dead:
                self._clients.remove(c)

    def _listen(self):
        """Accept Unix-socket connections from CLI / Electron UI."""
        if os.path.exists(self._socket_path):
            os.remove(self._socket_path)

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            srv.bind(self._socket_path)
            os.chmod(self._socket_path, 0o660)
            srv.listen(8)
            srv.settimeout(1.0)
            logger.info("IPC socket listening at %s", self._socket_path)

            while self._running:
                try:
                    conn, _ = srv.accept()
                    with self._client_lock:
                        self._clients.append(conn)
                    logger.debug("IPC client connected")
                except socket.timeout:
                    continue
        finally:
            srv.close()
            if os.path.exists(self._socket_path):
                os.remove(self._socket_path)
