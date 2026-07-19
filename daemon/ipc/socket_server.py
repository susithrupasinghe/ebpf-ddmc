"""
EDDMC - Unix Socket IPC Server

Serves the management API over a Unix domain socket at /var/run/eddmc.sock.
Uses HTTP over the socket — exactly the same approach as Docker.

Why Unix socket instead of TCP?
- Security: only local processes with filesystem access can connect;
  no network port is opened, no firewall rule needed.
- Permissions: standard file system ACLs control who can connect
  (e.g. chmod 660 + group "eddmc" for operator access without root).
- Performance: kernel-managed, no TCP stack overhead.
- Parity with Docker/containerd: operators already understand this model.

The Electron UI connects with Node's built-in http module using socketPath:
    http.get({ socketPath: '/var/run/eddmc.sock', path: '/api/processes' }, ...)
No change to the JSON API contract — only the transport changes.
"""

import json
import logging
import os
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler
from typing import Callable

logger = logging.getLogger("eddmc.ipc")

_START_TIME = time.time()
_MAX_HISTORY = 200


class _Handler(BaseHTTPRequestHandler):
    """
    HTTP request handler that works over a Unix socket.
    The API contract is identical to the previous TCP-based server.
    """

    # Injected by UnixSocketServer before serving
    process_store: dict           = {}
    store_lock:    threading.Lock = threading.Lock()
    detections:    list           = []
    alerts:        list           = []
    config:        dict           = {}
    # staticmethod() ensures these callables aren't auto-bound with `self` as
    # an implicit first argument when accessed via `self.revoke_cb(...)` etc.
    revoke_cb:     Callable       = staticmethod(lambda pid: None)
    kill_cb:       Callable       = staticmethod(lambda pid: None)
    update_detection_cb: Callable = staticmethod(lambda new_values: {})
    submit_allowlist_cb: Callable = staticmethod(lambda path, description: {})

    # ── Boilerplate overrides for Unix socket ──────────────────────────────
    def address_string(self):
        return "unix-socket"

    def log_message(self, fmt, *args):
        logger.debug(fmt, *args)

    # ── Response helpers ───────────────────────────────────────────────────
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

    # ── GET endpoints ──────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/api/status":
            self._json({
                "status":  "running",
                "uptime":  round(time.time() - _START_TIME, 1),
                "tracked": len(self.process_store),
                "transport": "unix-socket",
            })

        elif path == "/api/processes":
            with self.store_lock:
                procs = list(self.process_store.values())
            # Strip large raw event lists before serialising
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

    # ── POST endpoints ─────────────────────────────────────────────────────
    def do_POST(self):
        parts = self.path.strip("/").split("/")

        if len(parts) == 3 and parts[1] == "revoke":
            try:
                pid = int(parts[2])
                self.revoke_cb(pid)
                self._json({"ok": True, "pid": pid})
            except (ValueError, IndexError):
                self._json({"error": "bad pid"}, 400)

        elif len(parts) == 3 and parts[1] == "kill":
            try:
                pid = int(parts[2])
                self.kill_cb(pid)
                self._json({"ok": True, "pid": pid})
            except (ValueError, IndexError):
                self._json({"error": "bad pid"}, 400)

        elif len(parts) == 3 and parts[1] == "config" and parts[2] == "detection":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length)) if length else {}
            except (ValueError, json.JSONDecodeError):
                self._json({"error": "invalid JSON body"}, 400)
                return
            try:
                updated = self.update_detection_cb(body)
                self._json({"ok": True, "detection": updated})
            except Exception as exc:
                self._json({"error": str(exc)}, 400)

        elif len(parts) == 3 and parts[1] == "allowlist" and parts[2] == "submit":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length)) if length else {}
            except (ValueError, json.JSONDecodeError):
                self._json({"error": "invalid JSON body"}, 400)
                return
            path = body.get("path")
            if not path:
                self._json({"error": "'path' is required"}, 400)
                return
            try:
                result = self.submit_allowlist_cb(path, body.get("description"))
                self._json({"ok": True, **result})
            except Exception as exc:
                self._json({"error": str(exc)}, 400)

        else:
            self._json({"error": "not found"}, 404)


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """HTTP server bound to a Unix domain socket instead of a TCP port."""
    daemon_threads = True

    def get_request(self):
        # BaseHTTPRequestHandler expects (conn, (host, port)) — fake the address
        request, _ = super().get_request()
        return request, ("localhost", 0)


class UnixSocketServer:
    """
    Public interface: create, start, and stop the Unix socket HTTP server.
    """

    def __init__(
        self,
        socket_path:   str,
        process_store: dict,
        lock:          threading.Lock,
        detections:    list,
        alerts:        list,
        config:        dict,
        revoke_cb:     Callable,
        kill_cb:       Callable,
        update_detection_cb: Callable = lambda new_values: {},
        submit_allowlist_cb: Callable = lambda path, description: {},
    ):
        # Remove stale socket from previous run
        if os.path.exists(socket_path):
            os.remove(socket_path)

        _Handler.process_store = process_store
        _Handler.store_lock    = lock
        _Handler.detections    = detections
        _Handler.alerts        = alerts
        _Handler.config        = config
        # staticmethod() is required here: a plain function assigned as a class
        # attribute is a descriptor, so `self.revoke_cb(pid)` would silently
        # auto-bind `self` as the first argument (`revoke_cb(self, pid)`),
        # breaking every callback with a "too many positional arguments" error.
        _Handler.revoke_cb     = staticmethod(revoke_cb)
        _Handler.kill_cb       = staticmethod(kill_cb)
        _Handler.update_detection_cb = staticmethod(update_detection_cb)
        _Handler.submit_allowlist_cb = staticmethod(submit_allowlist_cb)

        self._server      = _UnixHTTPServer(socket_path, _Handler)
        self._socket_path = socket_path

        # World-accessible so Electron UI and CLI can connect without root
        os.chmod(socket_path, 0o666)
        logger.info("IPC socket: %s", socket_path)

    def start(self):
        t = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="ipc-server",
        )
        t.start()

    def stop(self):
        self._server.shutdown()
        if os.path.exists(self._socket_path):
            os.remove(self._socket_path)
