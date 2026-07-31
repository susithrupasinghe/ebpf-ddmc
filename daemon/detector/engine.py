"""
EDDMC - Detection Engine

Runs on a periodic timer, builds a BehaviouralFingerprint for each tracked
process, scores it, maintains a temporal profile (how many consecutive
scan windows the process has been suspicious), and dispatches mitigation.

Temporal logic
--------------
suspicious_ticks increments each scan window the process scores >= LOW.
It resets when the score drops back to NONE.  Mitigation escalates only
after sufficient sustained suspicion — this is the primary defence against
false positives from bursty legitimate workloads.
"""

import hashlib
import os
import threading
import time
import logging
from typing import Callable

from daemon.detector.fingerprint import (
    BehaviouralFingerprint, TemporalProfile, build as build_fingerprint
)
from daemon.detector.scorer import Scorer, ScoringResult

logger = logging.getLogger("eddmc.detector")

# Minimum score to increment suspicious_ticks
TICK_THRESHOLD = 20.0


def _own_thread_ids() -> set[int]:
    """
    TIDs of the daemon's own threads (its eBPF collector threads run
    in-process and share this PID) -- the syscall/sched/net/mem collector
    loops are themselves CPU-bound and futex-heavy, so without this they
    self-trigger the exact behavioural signature EDDMC looks for in miners.
    """
    try:
        return {int(t) for t in os.listdir(f"/proc/{os.getpid()}/task")}
    except OSError:
        return set()


def _resolve_exe(pid: int) -> str | None:
    try:
        return os.path.realpath(f"/proc/{pid}/exe")
    except OSError:
        return None


def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _is_allowlisted(
    pid: int,
    comm: str,
    allowlist_binaries: dict,
    allowlist_comm: set,
    registry_hashes: set = frozenset(),
    on_tamper: Callable[[int, str, str, str], None] = lambda pid, path, expected, actual: None,
) -> bool:
    """
    Skip scoring entirely for known-benign processes (e.g. dev tools whose
    multi-threaded, CPU/futex-heavy behaviour otherwise matches the mining
    signature closely enough to false-positive reliably).

    Two independent sources, checked in this order:

    1. allowlist_binaries: LOCAL, path-pinned. Maps exe path -> the SHA-256
       it had when trusted. Path alone is NOT enough: if malware can
       overwrite an allowlisted binary (e.g. a user-writable path),
       path-only matching would keep trusting it forever no matter what it
       now contains. Every match re-hashes the file and compares -- a path
       match with a hash MISMATCH is treated as a tamper signal (on_tamper),
       not silently allowlisted, since a previously-trusted binary's content
       changing is a classic sign of a supply-chain-style compromise.

    2. registry_hashes: a set of admin-confirmed known-good hashes pulled
       from the shared registry (see AllowlistSync) -- content-addressed
       only, no path association, since the same legitimate binary can live
       at different paths on different nodes. A process matches if its exe
       hash is in this set, regardless of where it's installed locally.
       There's no "tamper" concept here the way there is for #1: if a
       previously-matching binary's content changes, its new hash simply
       won't be in the set anymore and it falls back to normal scoring.

    Both are checked by resolving /proc/<pid>/exe, which is the same for
    every thread of a process -- so either check correctly exempts a whole
    multi-threaded application even though its individual worker threads
    each report a different `comm` (e.g. a Bun-based tool's threads show up
    as "Bun Pool 0", "HeapHelper", "mi-scavenger", etc; matching by comm name
    alone would miss most of them). comm-based matching (allowlist_comm) is
    offered for convenience but is inherently weaker: it's trivially
    spoofable (a miner can rename its own binary) and won't exempt a
    multi-threaded app's other worker threads either.
    """
    if comm in allowlist_comm:
        return True
    if not allowlist_binaries and not registry_hashes:
        return False

    exe = _resolve_exe(pid)
    if exe is None:
        return False

    if exe in allowlist_binaries:
        expected = allowlist_binaries[exe]
        actual = sha256_file(exe)
        if actual == expected:
            return True
        on_tamper(pid, exe, expected, actual)
        return False

    if registry_hashes:
        actual = sha256_file(exe)
        if actual in registry_hashes:
            return True

    return False

# Confidence-tier ranking used only to decide whether a fingerprint-registry
# match should elevate a process (distinct from the mitigation-tier ranking
# further down, which is a different label set: NONE/ALERT/THROTTLE/BLOCK/TERMINATE)
CONFIDENCE_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class DetectionEngine:
    def __init__(
        self,
        process_store:  dict,
        lock:           threading.Lock,
        on_detection:   Callable[[ScoringResult], None],
        on_mitigation:  Callable[[ScoringResult], None],
        scorer:         Scorer,
        interval_s:     float = 5.0,
        fingerprint_matcher=None,
        on_process_gone: Callable[[int], None] = lambda pid: None,
        get_detection_cfg: Callable[[], dict] = lambda: {},
        on_allowlist_tamper: Callable[[int, str, str, str], None] = lambda pid, path, expected, actual: None,
        allowlist_sync=None,
    ):
        self._store         = process_store
        self._lock          = lock
        self._on_detection  = on_detection
        self._on_process_gone = on_process_gone
        self._on_mitigation = on_mitigation
        self._scorer         = scorer
        self._interval      = interval_s
        self._matcher       = fingerprint_matcher
        self._get_detection_cfg = get_detection_cfg
        self._on_allowlist_tamper = on_allowlist_tamper
        self._allowlist_sync = allowlist_sync
        self._running       = False

        # pid → TemporalProfile (persistent across scans)
        self._temporal:  dict[int, TemporalProfile] = {}
        # pid → set of mitigation tiers already applied
        self._mitigated: dict[int, str] = {}

    def start(self):
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True, name="detection-engine")
        t.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            time.sleep(self._interval)
            try:
                self._scan()
            except Exception:
                # Uncaught here would silently kill this daemon thread forever
                # -- collectors/IPC keep running so nothing else looks wrong,
                # but no process would ever be scored again until restart.
                logger.exception("Unhandled error in detection scan -- continuing")

    def _scan(self):
        now = time.time()

        with self._lock:
            snapshot = list(self._store.items())

        own_tids  = _own_thread_ids()
        dead_pids = []

        detection_cfg = self._get_detection_cfg()
        allowlist_binaries = {
            entry["path"]: entry["sha256"]
            for entry in (detection_cfg.get("allowlist_binaries") or ())
        }
        allowlist_comm = set(detection_cfg.get("allowlist_comm") or ())
        registry_hashes = self._allowlist_sync.hashes() if self._allowlist_sync else set()

        for pid, data in snapshot:
            if pid in own_tids:
                continue
            # Collectors only ever add entries to the store, never remove
            # them -- without this check a dead pid's last-known data would
            # be rescored forever and never GC'd.
            if not os.path.exists(f"/proc/{pid}"):
                dead_pids.append(pid)
                continue
            if _is_allowlisted(
                pid, data.get("comm", ""), allowlist_binaries, allowlist_comm,
                registry_hashes=registry_hashes,
                on_tamper=self._on_allowlist_tamper,
            ):
                continue
            try:
                # ── Temporal profile ───────────────────────────────────────
                if pid not in self._temporal:
                    self._temporal[pid] = TemporalProfile(first_seen=now)
                temp = self._temporal[pid]
                temp.age_seconds = now - temp.first_seen

                # ── Build fingerprint and score ────────────────────────────
                fp     = build_fingerprint(pid, data, temp)
                result = self._scorer.score(fp)

                # ── Fingerprint-registry acceleration ──────────────────────
                # A cosine-similarity match against a confirmed variant
                # elevates straight to HIGH, skipping the normal observation
                # window -- the detection-acceleration benefit of the registry.
                if (
                    self._matcher is not None
                    and CONFIDENCE_RANK.get(result.confidence, 0) < CONFIDENCE_RANK["HIGH"]
                ):
                    match = self._matcher.match(fp)
                    if match:
                        result.confidence = "HIGH"
                        result.mitigation = "BLOCK"
                        result.score = max(result.score, 60.0)
                        result.reasons.append(
                            f"fingerprint registry match: {match['process_name']} "
                            f"(similarity={match['similarity']:.2f}) — elevated without "
                            f"waiting for full observation window"
                        )

                # ── Update temporal state ──────────────────────────────────
                temp.score_history.append(result.score)
                if len(temp.score_history) > 12:   # keep last 60 seconds
                    temp.score_history = temp.score_history[-12:]

                if result.score >= TICK_THRESHOLD:
                    temp.suspicious_ticks += 1
                else:
                    temp.suspicious_ticks = 0   # reset on clean window

                if len(temp.score_history) >= 3:
                    mean = sum(temp.score_history) / len(temp.score_history)
                    variance = sum((x - mean) ** 2 for x in temp.score_history) / len(temp.score_history)
                    temp.score_variance = variance

                # ── Update store ───────────────────────────────────────────
                with self._lock:
                    if pid in self._store:
                        self._store[pid]["score"]      = result.score
                        self._store[pid]["confidence"] = result.confidence
                        self._store[pid]["mitigation"] = result.mitigation
                        self._store[pid]["reasons"]    = result.reasons
                        self._store[pid]["ticks"]      = temp.suspicious_ticks
                        # Exposed for evaluation capture only (Chapter 6 data
                        # extraction, Task 7) -- fp.parallelism.cpu_percent was
                        # already computed for scoring but previously discarded
                        # once used, leaving no way to measure mitigation
                        # effect (CPU before/after enforcement) from capture
                        # CSVs alone. Read-only with respect to detection logic:
                        # nothing here changes what is scored or how.
                        self._store[pid]["cpu_percent"] = fp.parallelism.cpu_percent

                if result.confidence == "NONE":
                    self._mitigated.pop(pid, None)
                    continue

                # ── Emit detection event ───────────────────────────────────
                logger.info(
                    "[DETECT] pid=%d comm=%s score=%.1f conf=%s ticks=%d",
                    pid, result.comm, result.score,
                    result.confidence, temp.suspicious_ticks,
                )
                self._on_detection(result)

                # ── Dispatch mitigation (once per tier) ────────────────────
                prev_tier = self._mitigated.get(pid, "NONE")
                curr_tier = result.mitigation
                tier_rank = {"NONE": 0, "ALERT": 1, "THROTTLE": 2, "BLOCK": 3, "TERMINATE": 4}

                if tier_rank.get(curr_tier, 0) > tier_rank.get(prev_tier, 0):
                    self._mitigated[pid] = curr_tier
                    self._on_mitigation(result)

            except Exception as exc:
                logger.debug("Scoring error for pid %d: %s", pid, exc)

        # ── GC dead processes ────────────────────────────────────────────────
        # A pid that exits on its own (not revoked manually via the API)
        # would otherwise leave its cgroup/iptables mitigations -- and its
        # row in the shared store -- in place forever. Lift them the same
        # way a manual revoke would, and drop the store entry so it stops
        # being rescored.
        for pid in dead_pids:
            if pid in self._mitigated:
                try:
                    self._on_process_gone(pid)
                except Exception:
                    logger.exception("Error revoking mitigations for exited pid %d", pid)
            self._mitigated.pop(pid, None)
            self._temporal.pop(pid, None)
            with self._lock:
                self._store.pop(pid, None)

        live_pids = set(pid for pid, _ in snapshot) - set(dead_pids)
        for pid in list(self._temporal.keys()):
            if pid not in live_pids:
                del self._temporal[pid]
                if pid in self._mitigated:
                    try:
                        self._on_process_gone(pid)
                    except Exception:
                        logger.exception("Error revoking mitigations for exited pid %d", pid)
                self._mitigated.pop(pid, None)
