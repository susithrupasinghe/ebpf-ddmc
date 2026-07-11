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
import logging
import os
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.config.config                 import load as load_config
from daemon.collector.syscall_collector   import SyscallCollector
from daemon.collector.sched_collector     import SchedCollector
from daemon.collector.net_collector       import NetCollector
from daemon.collector.mem_collector       import MemCollector
from daemon.detector.engine               import DetectionEngine
from daemon.mitigator.policy              import MitigationPolicy
from daemon.alerts.alerter                import AlertBus  # JSONL file log
from daemon.ipc.socket_server             import UnixSocketServer
from daemon.fingerprint.assessor          import FingerprintAssessor
from daemon.fingerprint.packager          import package as package_fingerprint
from daemon.fingerprint.submitter         import FingerprintSubmitter
from daemon.fingerprint.matcher           import FingerprintMatcher


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
            )
            submitter = FingerprintSubmitter(fp_cfg["registry_url"])
            matcher = FingerprintMatcher(
                registry_url=fp_cfg["registry_url"],
                threshold=fp_cfg.get("similarity_threshold", 0.85),
                refresh_interval_hours=fp_cfg.get("refresh_interval_hours", 1),
            )
            matcher.start()
            logger.info("Fingerprint registry enabled: %s", fp_cfg["registry_url"])

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
        engine = DetectionEngine(
            process_store=self._store,
            lock=self._lock,
            on_detection=on_detection,
            on_mitigation=on_mitigation,
            interval_s=cfg["daemon"]["scan_interval"],
            fingerprint_matcher=matcher,
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
