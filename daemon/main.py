"""
EDDMC Daemon - Main Entry Point

Orchestrates:
  1. eBPF collectors (syscall, sched, net, mem)
  2. Behavioural fingerprinting + deterministic scoring
  3. Mitigation policy engine
  4. Alert bus (Unix socket streaming + JSONL log)
  5. Unix socket HTTP IPC server (Docker-style, for Electron UI and CLI)

Must be run as root (required for eBPF + cgroups + iptables).
"""

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.config.config                 import load as load_config, save_local_override, deep_merge
from daemon.collector.syscall_collector   import SyscallCollector
from daemon.collector.sched_collector     import SchedCollector
from daemon.collector.net_collector       import NetCollector
from daemon.collector.mem_collector       import MemCollector
from daemon.detector.scorer               import Scorer
from daemon.detector.engine               import DetectionEngine, sha256_file
from daemon.mitigator.policy              import MitigationPolicy
from daemon.alerts.alerter                import AlertBus  # JSONL file log
from daemon.ipc.socket_server             import UnixSocketServer
from daemon.fingerprint.assessor          import FingerprintAssessor
from daemon.fingerprint.packager          import package as package_fingerprint, node_id
from daemon.fingerprint.submitter         import FingerprintSubmitter
from daemon.fingerprint.matcher           import FingerprintMatcher
from daemon.fingerprint.allowlist_sync    import AllowlistSync


def setup_logging(level: str, log_file: str | None):
    fmt = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    handlers = [logging.StreamHandler(sys.stderr)]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt, handlers=handlers,
    )


def check_root():
    if os.geteuid() != 0:
        print("EDDMC requires root privileges (eBPF + cgroups + iptables).")
        sys.exit(1)


class EDDMCDaemon:
    def __init__(self, cfg: dict):
        self._cfg      = cfg
        self._running  = False
        self._store    = {}
        self._lock     = threading.Lock()
        self._detections: list = []
        self._alerts:     list = []

    def start(self):
        cfg    = self._cfg
        logger = logging.getLogger("eddmc.daemon")
        logger.info("EDDMC starting — pid=%d", os.getpid())

        # ── Alert bus ──────────────────────────────────────────────────────
        log_file = cfg["daemon"].get("log_file", "")
        alert_log = log_file.replace("eddmc.log", "alerts.jsonl") if log_file \
                    else "/var/log/eddmc/alerts.jsonl"

        alert_bus = AlertBus(log_path=alert_log)
        alert_bus.start()

        def on_alert(alert: dict):
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-500:]
            alert_bus.push(alert)

        # ── Mitigation policy ──────────────────────────────────────────────
        policy = MitigationPolicy(
            alert_cb=on_alert,
            auto_kill=cfg["mitigation"]["auto_kill"],
            dry_run=cfg["mitigation"]["dry_run"],
        )

        # ── Distributed Behavioural Fingerprint Registry (opt-in) ──────────
        fp_cfg      = cfg.get("fingerprint_registry", {})
        fp_enabled  = fp_cfg.get("enabled", False)
        assessor    = None
        submitter   = None
        matcher     = None

        if fp_enabled:
            assessor = FingerprintAssessor(
                sustained_critical_seconds=fp_cfg.get("sustained_critical_seconds", 60),
                min_syscalls=cfg.get("detection", {}).get("min_syscalls", 500),
            )
            submitter = FingerprintSubmitter(fp_cfg["registry_url"])
            matcher = FingerprintMatcher(
                registry_url=fp_cfg["registry_url"],
                threshold=fp_cfg.get("similarity_threshold", 0.85),
                refresh_interval_hours=fp_cfg.get("refresh_interval_hours", 1),
            )
            matcher.start()
            logger.info("Fingerprint registry enabled: %s", fp_cfg["registry_url"])

        # Separate opt-in: syncing the registry's admin-confirmed allowlist
        # (false positives reduction) is independent of the miner-fingerprint
        # channel above (detection acceleration) -- an operator may want one
        # without the other -- though both use the same registry_url.
        allowlist_sync = None
        if fp_cfg.get("sync_allowlist", False):
            registry_url = fp_cfg.get("registry_url")
            if not registry_url:
                logger.error("fingerprint_registry.sync_allowlist is true but registry_url is not set")
            else:
                allowlist_sync = AllowlistSync(
                    registry_url=registry_url,
                    refresh_interval_hours=fp_cfg.get("refresh_interval_hours", 1),
                )
                allowlist_sync.start()
                logger.info("Registry allowlist sync enabled: %s", registry_url)

        def submit_allowlist_to_registry(path: str, description: str) -> dict:
            """Admin action (via `eddmc allowlist submit`) -- never automatic."""
            registry_url = fp_cfg.get("registry_url")
            if not registry_url:
                raise ValueError("fingerprint_registry.registry_url is not configured")
            digest = sha256_file(path)
            if digest is None:
                raise ValueError(f"cannot read {path}")
            body = json.dumps({
                "sha256": digest, "description": description, "node_id": node_id(),
            }).encode()
            req = urllib.request.Request(
                registry_url.rstrip("/") + "/api/v1/allowlist",
                data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                result = json.loads(resp.read())
            logger.info("Submitted %s (%s) to registry allowlist: %s", path, digest[:12], result.get("status"))
            return {**result, "sha256": digest, "path": path}

        def on_detection(result):
            self._detections.append({
                "pid":        result.pid,
                "comm":       result.comm,
                "score":      result.score,
                "confidence": result.confidence,
                "reasons":    result.reasons,
                "timestamp":  time.time(),
            })
            if len(self._detections) > 500:
                self._detections = self._detections[-500:]

            if assessor is not None:
                evidence = assessor.evaluate(result)
                if evidence is not None:
                    fingerprint = package_fingerprint(result.fingerprint, evidence)
                    logger.info(
                        "Fingerprint gate PASSED for pid=%d (%s) — submitting to registry",
                        result.pid, result.comm,
                    )
                    submitter.submit_async(fingerprint)

        def on_mitigation(result):
            policy.apply(result)

        # ── eBPF Collectors ────────────────────────────────────────────────
        logger.info("Loading eBPF programs…")
        collectors = []
        try:
            for Cls, name in [
                (SyscallCollector, "syscall"),
                (SchedCollector,   "sched"),
                (NetCollector,     "net"),
                (MemCollector,     "mem"),
            ]:
                c = Cls(self._store, self._lock)
                c.load()
                c.start()
                collectors.append(c)
                logger.info("  [OK] %s collector", name)
        except Exception as e:
            logger.error("Failed to load eBPF programs: %s", e)
            sys.exit(1)

        logger.info("All eBPF collectors running")

        # ── Detection engine ───────────────────────────────────────────────
        scorer = Scorer(cfg.get("detection"))

        def update_detection_config(new_values: dict) -> dict:
            """
            Live-retune scoring weights/floors/tier-thresholds/allowlist (e.g.
            from the UI's config panel) with no daemon restart, and persist
            to local.yaml so it survives one.
            """
            new_values = dict(new_values)

            # Convenience: accept plain paths and hash-pin them at add time
            # ("trust on first use") rather than requiring the caller to
            # compute a SHA-256 themselves. Merges with any existing
            # allowlist_binaries entries instead of clobbering them.
            if "allowlist_paths" in new_values:
                by_path = {
                    e["path"]: e
                    for e in cfg.get("detection", {}).get("allowlist_binaries", [])
                }
                for path in new_values.pop("allowlist_paths"):
                    digest = sha256_file(path)
                    if digest is None:
                        raise ValueError(f"cannot read {path} to hash it")
                    by_path[path] = {"path": path, "sha256": digest}
                new_values["allowlist_binaries"] = list(by_path.values())

            cfg["detection"] = deep_merge(cfg.get("detection", {}), new_values)
            scorer.update(cfg["detection"])
            save_local_override("detection", cfg["detection"])
            logger.info("Detection config updated live: %s", new_values)
            return cfg["detection"]

        def on_allowlist_tamper(pid: int, path: str, expected: str, actual: str):
            logger.error(
                "[TAMPER] pid=%d exe=%s hash mismatch (expected=%s actual=%s) -- "
                "an allowlisted binary's content changed since it was trusted; "
                "no longer exempting it from scoring",
                pid, path, expected[:12], (actual or "unreadable")[:12],
            )
            on_alert({
                "pid": pid, "comm": "",
                "score": 100.0, "confidence": "CRITICAL", "action": "TAMPER_DETECTED",
                "reasons": [f"allowlisted binary {path} hash changed: expected {expected[:12]}, got {(actual or 'unreadable')[:12]}"],
                "timestamp": time.time(),
            })

        engine = DetectionEngine(
            process_store=self._store,
            lock=self._lock,
            on_detection=on_detection,
            on_mitigation=on_mitigation,
            scorer=scorer,
            interval_s=cfg["daemon"]["scan_interval"],
            fingerprint_matcher=matcher,
            on_process_gone=lambda pid: policy.revoke(pid),
            get_detection_cfg=lambda: cfg.get("detection", {}),
            on_allowlist_tamper=on_allowlist_tamper,
            allowlist_sync=allowlist_sync,
        )
        engine.start()

        # ── Unix socket IPC server (HTTP over socket, like Docker) ─────────
        from daemon.mitigator.terminator import terminate
        ipc = UnixSocketServer(
            socket_path=cfg["daemon"]["socket_path"],
            process_store=self._store,
            lock=self._lock,
            detections=self._detections,
            alerts=self._alerts,
            config=cfg,
            revoke_cb=lambda pid: policy.revoke(pid),
            kill_cb=lambda pid: terminate(pid),
            update_detection_cb=update_detection_config,
            submit_allowlist_cb=submit_allowlist_to_registry,
        )
        ipc.start()
        logger.info("IPC server: %s", cfg["daemon"]["socket_path"])

        # ── Signal handling ────────────────────────────────────────────────
        self._running = True

        def _shutdown(sig, frame):
            logger.info("Received signal %d — shutting down…", sig)
            self._running = False

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT,  _shutdown)

        logger.info("EDDMC running. Press Ctrl-C or SIGTERM to stop.")

        while self._running:
            time.sleep(1)

        # ── Teardown ───────────────────────────────────────────────────────
        engine.stop()
        for c in collectors:
            c.stop()
        if matcher is not None:
            matcher.stop()
        if allowlist_sync is not None:
            allowlist_sync.stop()
        alert_bus.stop()
        ipc.stop()
        logger.info("EDDMC stopped.")


def main():
    parser = argparse.ArgumentParser(
        description="EDDMC — eBPF-based CPU Cryptojacking Detection Daemon"
    )
    parser.add_argument("--config",    metavar="PATH")
    parser.add_argument("--dry-run",   action="store_true")
    parser.add_argument("--log-level", default=None,
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    check_root()
    cfg = load_config(args.config)
    if args.dry_run:
        cfg["mitigation"]["dry_run"] = True
    if args.log_level:
        cfg["daemon"]["log_level"] = args.log_level

    setup_logging(cfg["daemon"]["log_level"], cfg["daemon"].get("log_file"))
    EDDMCDaemon(cfg).start()


if __name__ == "__main__":
    main()
