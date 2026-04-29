"""
EDDMC - HTTP API Server

Exposes a lightweight JSON REST API on localhost for the Electron UI.
Runs inside the daemon process on a background thread.

Endpoints
---------
GET  /api/status          Daemon health + uptime
GET  /api/processes       All tracked processes with scores
GET  /api/detections      Recent detection events (last 200)
GET  /api/alerts          Recent alert log (last 200)
POST /api/revoke/<pid>    Manually lift mitigations from a PID
POST /api/kill/<pid>      Manually terminate a PID
GET  /api/config          Current running configuration
"""

import json
import threading
import time
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable

logger = logging.getLogger("eddmc.api")

_START_TIME = time.time()
_MAX_HISTORY = 200


class _Handler(BaseHTTPRequestHandler):
    """Minimal HTTP handler — no framework dependency."""

    # Injected by APIServer.start()
    process_store: dict       = {}
    store_lock:    threading.Lock = threading.Lock()
    detections:    list        = []
    alerts:        list        = []
    config:        dict        = {}
    revoke_cb:     Callable    = lambda pid: None
    kill_cb:       Callable    = lambda pid: None

    def log_message(self, fmt, *args):
        logger.debug(fmt, *args)

    def _json(self, obj, status=200):
        body = json.dumps(obj, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/api/status":
            self._json({
                "status":  "running",
                "uptime":  round(time.time() - _START_TIME, 1),
                "tracked": len(self.process_store),
            })

        elif path == "/api/processes":
            with self.store_lock:
                procs = list(self.process_store.values())
            # Strip large event lists before sending
            slim = []
            for p in procs:
                entry = {k: v for k, v in p.items() if k != "syscall_events"}
                slim.append(entry)
            self._json(slim)

        elif path == "/api/detections":
            self._json(self.detections[-_MAX_HISTORY:])

        elif path == "/api/alerts":
            self._json(self.alerts[-_MAX_HISTORY:])

        elif path == "/api/config":
            self._json(self.config)

        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        # /api/revoke/<pid>
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "revoke":
            try:
                pid = int(parts[2])
                self.revoke_cb(pid)
                self._json({"ok": True, "pid": pid})
            except (ValueError, IndexError):
                self._json({"error": "bad pid"}, 400)

        # /api/kill/<pid>
        elif len(parts) == 3 and parts[0] == "api" and parts[1] == "kill":
            try:
                pid = int(parts[2])
                self.kill_cb(pid)
                self._json({"ok": True, "pid": pid})
            except (ValueError, IndexError):
                self._json({"error": "bad pid"}, 400)

        else:
            self._json({"error": "not found"}, 404)


class APIServer:
    def __init__(
        self,
        process_store: dict,
        lock:          threading.Lock,
        detections:    list,
        alerts:        list,
        config:        dict,
        revoke_cb:     Callable,
        kill_cb:       Callable,
        port:          int = 7373,
    ):
        _Handler.process_store = process_store
        _Handler.store_lock    = lock
        _Handler.detections    = detections
        _Handler.alerts        = alerts
        _Handler.config        = config
        _Handler.revoke_cb     = revoke_cb
        _Handler.kill_cb       = kill_cb

        self._server = HTTPServer(("127.0.0.1", port), _Handler)

    def start(self):
        t = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="api-server",
        )
        t.start()
        logger.info("API server listening on http://127.0.0.1:%d", self._server.server_address[1])

    def stop(self):
        self._server.shutdown()
