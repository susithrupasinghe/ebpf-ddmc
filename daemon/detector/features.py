"""
EDDMC - Feature Extractor

Converts raw per-process kernel event data (syscall counts, scheduler
stats, network observations) into a normalized feature vector that the
scoring engine can evaluate.

Cryptominer fingerprint rationale
----------------------------------
futex_ratio      HIGH   Miners use heavy mutex/barrier synchronisation across
                        hashing threads; futex dominates their syscall mix.
io_ratio         LOW    Miners compute, not I/O.  read+write syscalls are rare
                        relative to total syscall volume.
clone_count      MEDIUM One clone() per logical CPU at startup is the canonical
                        miner thread-launch pattern.
nanosleep_ratio  MEDIUM Throttling miners sleep periodically; aggressive miners
                        never sleep.  Both are anomalous in different ways.
cpu_bound_ratio  HIGH   involuntary_switches / total_switches → near 1.0 means
                        the process never voluntarily yields (CPU-bound).
thread_count     MEDIUM Matches logical CPU count for full-utilisation miners.
mmap_ratio       MEDIUM Large scratch-buffer allocations for hash state.
pool_hits        HIGH   Direct connection to a known stratum port → very strong
                        signal regardless of other features.
"""

import os
import math
import time
import psutil


def extract(pid: int, proc_data: dict) -> dict:
    """
    Returns a normalised feature dict from the current proc_data snapshot.
    All ratio features are in [0.0, 1.0].  Raw count features are clamped.
    """
    sc = proc_data.get("syscall_counts", {})
    sched = proc_data.get("sched", {})
    net = proc_data.get("net", {})

    total_sc = max(sc.get("total", 0), 1)

    # --- Syscall ratio features ---
    futex_ratio     = sc.get("futex", 0)     / total_sc
    read_write      = sc.get("read", 0) + sc.get("write", 0)
    io_ratio        = read_write               / total_sc
    mmap_ratio      = (sc.get("mmap", 0) + sc.get("mprotect", 0)) / total_sc
    nanosleep_ratio = sc.get("nanosleep", 0)  / total_sc
    clone_count     = sc.get("clone", 0)
    connect_count   = sc.get("connect", 0)

    # --- Scheduler features ---
    vol   = sched.get("voluntary_switches", 0)
    invol = sched.get("involuntary_switches", 0)
    total_sw = max(vol + invol, 1)
    cpu_bound_ratio  = invol / total_sw
    thread_count     = sched.get("thread_count", 1)
    on_cpu_ns        = sched.get("on_cpu_ns", 0)

    # --- Network features ---
    pool_hits        = net.get("mining_pool_hits", 0)
    total_conn       = max(net.get("total_connections", 0), 1)
    pool_ratio       = pool_hits / total_conn

    # --- System context ---
    cpu_count        = os.cpu_count() or 1
    # thread_density: how close is thread_count to CPU core count
    thread_density   = min(thread_count / cpu_count, 2.0) / 2.0  # [0,1]

    # --- CPU usage from /proc (complements eBPF on_cpu_ns) ---
    cpu_percent = _get_cpu_percent(pid)

    return {
        "futex_ratio":      round(futex_ratio, 4),
        "io_ratio":         round(io_ratio, 4),
        "mmap_ratio":       round(mmap_ratio, 4),
        "nanosleep_ratio":  round(nanosleep_ratio, 4),
        "clone_count":      clone_count,
        "connect_count":    connect_count,
        "cpu_bound_ratio":  round(cpu_bound_ratio, 4),
        "thread_count":     thread_count,
        "thread_density":   round(thread_density, 4),
        "pool_hits":        pool_hits,
        "pool_ratio":       round(pool_ratio, 4),
        "cpu_percent":      round(cpu_percent, 2),
        "on_cpu_ns":        on_cpu_ns,
        "total_syscalls":   sc.get("total", 0),
    }


# Cache for psutil Process objects (avoid repeated lookups)
_proc_cache: dict = {}

def _get_cpu_percent(pid: int) -> float:
    try:
        if pid not in _proc_cache:
            _proc_cache[pid] = psutil.Process(pid)
        return _proc_cache[pid].cpu_percent(interval=None)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        _proc_cache.pop(pid, None)
        return 0.0
