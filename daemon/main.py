"""
EDDMC Daemon - Main Entry Point

Orchestrates:
  1. eBPF collectors (syscall, sched, net)
  2. Detection engine (behavioral fingerprinting + scoring)
  3. Mitigation policy engine
  4. Alert bus (IPC socket + log)
  5. HTTP API server (for Electron UI)

Must be run as root (required for eBPF + cgroups + iptables).
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time

# Ensure project root is on path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.config.config          import load as load_config
from daemon.collector.syscall_collector import SyscallCollector
from daemon.collector.sched_collector   import SchedCollector
from daemon.collector.net_collector     import NetCollector
from daemon.detector.engine             import DetectionEngine
from daemon.mitigator.policy            import MitigationPolicy
from daemon.alerts.alerter              import AlertBus
from daemon.api_server                  import APIServer


def setup_logging(level: str, log_file: str | None):
    fmt = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    handlers = [logging.StreamHandler(sys.stderr)]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
                        format=fmt, handlers=handlers)


def check_root():
    if os.geteuid() != 0:
        print("EDDMC requires root privileges (eBPF + cgroups + iptables).")
        sys.exit(1)


class EDDMCDaemon:
    def __init__(self, cfg: dict):
        self._cfg      = cfg
        self._running  = False

        # Shared state store: pid → process data dict
        self._store    = {}
        self._lock     = threading.Lock()

        # Detection history for UI
        self._detections: list = []
        self._alerts:     list = []

    def start(self):
        cfg = self._cfg
        logger = logging.getLogger("eddmc.daemon")
        logger.info("EDDMC starting — pid=%d", os.getpid())

        # ── Alert bus ──────────────────────────────────────────────────────
        alert_bus = AlertBus(
            socket_path=cfg["daemon"]["socket_path"],
            log_path=cfg["daemon"].get("log_file", "/var/log/eddmc/alerts.jsonl")
                        .replace("eddmc.log", "alerts.jsonl"),
        )
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

        # ── Detection callbacks ────────────────────────────────────────────
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

        def on_mitigation(result):
            policy.apply(result)

        # ── eBPF Collectors ────────────────────────────────────────────────
        logger.info("Loading eBPF programs…")
        try:
            sc_collector = SyscallCollector(self._store, self._lock)
            sc_collector.load()
            sc_collector.start()

            sched_collector = SchedCollector(self._store, self._lock)
            sched_collector.load()
            sched_collector.start()

            net_collector = NetCollector(self._store, self._lock)
            net_collector.load()
            net_collector.start()
        except Exception as e:
            logger.error("Failed to load eBPF programs: %s", e)
            sys.exit(1)

        logger.info("eBPF collectors running")

        # ── Detection engine ───────────────────────────────────────────────
        engine = DetectionEngine(
            process_store=self._store,
            lock=self._lock,
            on_detection=on_detection,
            on_mitigation=on_mitigation,
            interval_s=cfg["daemon"]["scan_interval"],
        )
        engine.start()

        # ── HTTP API server ────────────────────────────────────────────────
        api = APIServer(
            process_store=self._store,
            lock=self._lock,
            detections=self._detections,
            alerts=self._alerts,
            config=cfg,
            revoke_cb=lambda pid: policy.revoke(pid),
            kill_cb=lambda pid: __import__(
                "daemon.mitigator.terminator", fromlist=["terminate"]
            ).terminate(pid),
            port=cfg["ui"]["api_port"],
        )
        api.start()

        # ── Signal handling ────────────────────────────────────────────────
        self._running = True

        def _shutdown(sig, frame):
            logger.info("Received signal %d — shutting down…", sig)
            self._running = False

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT,  _shutdown)

        logger.info("EDDMC running. Press Ctrl-C or send SIGTERM to stop.")

        # ── Main loop ──────────────────────────────────────────────────────
        while self._running:
            time.sleep(1)

        # ── Teardown ───────────────────────────────────────────────────────
        engine.stop()
        sc_collector.stop()
        sched_collector.stop()
        net_collector.stop()
        alert_bus.stop()
        api.stop()
        logger.info("EDDMC stopped cleanly.")


def main():
    parser = argparse.ArgumentParser(
        description="EDDMC — eBPF-based CPU Cryptojacking Detection Daemon"
    )
    parser.add_argument("--config",   metavar="PATH",
                        help="Path to YAML config file (overrides defaults)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Detect but do not apply any mitigations")
    parser.add_argument("--log-level", default=None,
                        choices=["DEBUG","INFO","WARNING","ERROR"],
                        help="Override log level from config")
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
