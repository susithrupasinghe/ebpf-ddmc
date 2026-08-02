"""
EDDMC - Fingerprint Packager

Builds the normalised, privacy-preserving JSON fingerprint object that is
submitted to the Distributed Behavioural Fingerprint Registry. No file
paths, process arguments, usernames or network addresses are included --
only ratios derived from kernel event counts, a one-way node hash, and
(optionally) a SHA-256 of the miner binary.

`feature_vector()` is the single source of truth for the 8-dimension
vector shared between submission (here) and lookup (matcher.py). It
adapts the thesis's named feature list to what BehaviouralFingerprint
actually carries: fingerprint.py's MemoryProfile tracks a discrete
RandomX scratchpad allocation count rather than a continuous mmap
syscall ratio, so `randomx_signature` (a 0/1 indicator) is used in place
of the thesis's `mmap_ratio` term -- same discriminative signal, simpler
representation.
"""

from __future__ import annotations

import hashlib
import socket
import time
from typing import Optional

from daemon.detector.fingerprint import BehaviouralFingerprint

EDDMC_VERSION = "0.1.0"

FEATURE_NAMES = [
    "futex_ratio",
    "io_ratio",
    "nanosleep_ratio",
    "cpu_bound_ratio",
    "thread_cpu_ratio",  # was mislabelled "thread_density" -- feature_vector() below computes
                         # min(thread_cpu_ratio, 2.0), the raw [0,2] ratio, NOT the dissertation's
                         # normalised [0,1] thread_density (= thread_cpu_ratio / 2.0). Renamed to
                         # match what is actually submitted, rather than changing the value and
                         # risking inconsistency with any fingerprint already in the registry.
    "cpu_percent",
    "randomx_signature",
    "pool_hit",
]


def feature_vector(fp: BehaviouralFingerprint) -> list[float]:
    sc, par, mem, sch, net = (
        fp.syscall,
        fp.parallelism,
        fp.memory,
        fp.scheduler,
        fp.network,
    )
    return [
        round(sc.futex_ratio, 4),
        round(sc.io_ratio, 4),
        round(sc.nanosleep_ratio, 4),
        round(sch.cpu_bound_ratio, 4),
        round(min(par.thread_cpu_ratio, 2.0), 4),
        round(min(par.cpu_percent / 100.0, 1.0), 4),
        1.0 if mem.scratchpad_allocs > 0 else 0.0,
        1.0 if net.pool_connections > 0 else 0.0,
    ]


def binary_hash(pid: int) -> Optional[str]:
    """Best-effort SHA-256 of the process binary. None if inaccessible --
    absence never blocks a submission, per the confirmation gate design."""
    try:
        with open(f"/proc/{pid}/exe", "rb") as f:
            data = f.read()
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return None


def node_id() -> str:
    """One-way hash of the hostname -- the registry never learns which
    physical host submitted a fingerprint."""
    return hashlib.sha256(socket.gethostname().encode()).hexdigest()


def package(fp: BehaviouralFingerprint, evidence: dict) -> dict:
    vector = feature_vector(fp)
    fingerprint_id = hashlib.sha256(
        ",".join(f"{v:.4f}" for v in vector).encode()
    ).hexdigest()

    return {
        "fingerprint_id": fingerprint_id,
        "node_id": node_id(),
        "submitted_at": time.time(),
        "eddmc_version": EDDMC_VERSION,
        "kernel_version": _kernel_version(),
        "process_name": fp.comm,
        "score_at_submission": evidence.get("score"),
        "feature_names": FEATURE_NAMES,
        "feature_vector": vector,
        "evidence": {
            "sustained_seconds": evidence.get("sustained_seconds"),
            "pool_connection_count": fp.network.pool_connections,
            "binary_sha256": evidence.get("binary_sha256"),
        },
    }


def _kernel_version() -> str:
    import platform

    return platform.release()
