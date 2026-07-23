"""
EDDMC - Behavioural Fingerprint Model

A behavioural fingerprint is a multi-dimensional profile of how a process
interacts with the Linux kernel, constructed from eBPF-captured telemetry.
It differs from signature-based detection: we identify WHAT THE PROCESS DOES,
not what the binary IS.

Five fingerprint dimensions
---------------------------

1. SYSCALL FINGERPRINT
   The syscall mix of a CPU cryptominer is highly specific:
   - futex dominates (40-80%) — thread barrier synchronisation between hash rounds
   - read + write nearly absent (<2%) — miners compute, never do file I/O
   - clone count ≈ CPU core count — spawned exactly once at startup
   - nanosleep: absent (aggressive) or periodic (throttled) — both detectable

2. PARALLELISM FINGERPRINT
   - thread_count ≈ logical CPU count — full utilisation is the goal
   - all threads simultaneously CPU-bound (involuntary preemptions dominate)
   - no voluntary yields to I/O or sleep

3. MEMORY FINGERPRINT (RandomX-specific)
   - Exactly N × 2,097,152 byte anonymous private mappings at startup
     (one 2MB scratchpad per hash thread — this is the RandomX algorithm requirement)
   - Large mprotect() calls on these regions
   - Working set is STABLE — no growth after initialisation
   - Contrast: compilers grow memory continuously; databases have variable working sets

4. SCHEDULER FINGERPRINT
   - cpu_saturation: on_cpu_ns / elapsed_ns → near 1.0
   - involuntary_ratio: involuntary_switches / total_switches → >0.95
   - Miners are among the most CPU-bound workloads on any Linux system

5. TEMPORAL FINGERPRINT (most important for evasion resistance)
   - A miner must maintain its profile CONTINUOUSLY to generate revenue
   - Throttled miners that lower CPU every N seconds still show a PERIODIC pattern
   - Legitimate bursty workloads (builds, renders) drop off within minutes
   - We require the fingerprint to be SUSTAINED across multiple scan windows
     before escalating mitigation — this eliminates almost all false positives

6. NETWORK FINGERPRINT
   - Connection to stratum port (3333/4444/etc.) is near-conclusive
   - But absence does not clear suspicion — air-gapped solo miners exist
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import os
import time


@dataclass
class SyscallProfile:
    futex_ratio:      float = 0.0   # futex / total syscalls
    io_ratio:         float = 0.0   # (read+write) / total
    compute_purity:   float = 0.0   # 1 - io_ratio (how compute-only)
    clone_count:      int   = 0     # total clone() calls
    nanosleep_ratio:  float = 0.0
    total_syscalls:   int   = 0


@dataclass
class ParallelismProfile:
    thread_count:     int   = 1
    thread_cpu_ratio: float = 0.0   # thread_count / cpu_count
    cpu_percent:      float = 0.0


@dataclass
class MemoryProfile:
    scratchpad_allocs:      int   = 0   # N x 2MB anon-private mappings (size match alone -- weak, see scratchpad_huge_allocs)
    scratchpad_huge_allocs: int   = 0   # size match AND MAP_HUGETLB together -- the strong RandomX signal
    total_anon_mb:          float = 0.0 # total MB of anon-private mappings
    huge_page_requests:     int   = 0
    working_set_stable:     bool  = False # True after 30s with no new large allocs
    scratchpad_mb:          float = 0.0 # scratchpad_allocs × 2


@dataclass
class SchedulerProfile:
    cpu_bound_ratio:      float = 0.0   # involuntary / (involuntary + voluntary)
    on_cpu_ns:            int   = 0
    involuntary_switches: int   = 0
    voluntary_switches:   int   = 0


@dataclass
class TemporalProfile:
    first_seen:           float = 0.0   # unix timestamp
    suspicious_ticks:     int   = 0     # consecutive scan windows above threshold
    score_history:        list  = field(default_factory=list)  # last 12 scores
    score_variance:       float = 0.0   # low = consistent miner, high = bursty
    age_seconds:          float = 0.0


@dataclass
class NetworkProfile:
    pool_connections:     int   = 0     # confirmed stratum port hits
    total_connections:    int   = 0


@dataclass
class BehaviouralFingerprint:
    pid:          int
    comm:         str
    syscall:      SyscallProfile      = field(default_factory=SyscallProfile)
    parallelism:  ParallelismProfile  = field(default_factory=ParallelismProfile)
    memory:       MemoryProfile       = field(default_factory=MemoryProfile)
    scheduler:    SchedulerProfile    = field(default_factory=SchedulerProfile)
    temporal:     TemporalProfile     = field(default_factory=TemporalProfile)
    network:      NetworkProfile      = field(default_factory=NetworkProfile)


def build(pid: int, proc_data: dict, temporal: TemporalProfile) -> BehaviouralFingerprint:
    """
    Constructs a BehaviouralFingerprint from the raw process data collected
    by the eBPF collectors.
    """
    sc    = proc_data.get("syscall_counts", {})
    sched = proc_data.get("sched", {})
    net   = proc_data.get("net", {})
    mem   = proc_data.get("mem", {})
    comm  = proc_data.get("comm", "")

    total_sc   = max(sc.get("total", 0), 1)
    cpu_count  = os.cpu_count() or 1

    # ── Syscall profile ────────────────────────────────────────────────────
    futex      = sc.get("futex", 0)
    reads      = sc.get("read",  0)
    writes     = sc.get("write", 0)
    syscall_p  = SyscallProfile(
        futex_ratio     = futex / total_sc,
        io_ratio        = (reads + writes) / total_sc,
        compute_purity  = 1.0 - (reads + writes) / total_sc,
        clone_count     = sc.get("clone", 0),
        nanosleep_ratio = sc.get("nanosleep", 0) / total_sc,
        total_syscalls  = sc.get("total", 0),
    )

    # ── Parallelism profile ────────────────────────────────────────────────
    threads    = max(sched.get("thread_count", 1), 1)
    cpu_pct    = _cpu_percent(pid)
    parallel_p = ParallelismProfile(
        thread_count     = threads,
        thread_cpu_ratio = min(threads / cpu_count, 2.0),
        cpu_percent      = cpu_pct,
    )

    # ── Memory profile ─────────────────────────────────────────────────────
    scratchpad_allocs      = mem.get("scratchpad_allocs", 0)
    scratchpad_huge_allocs = mem.get("scratchpad_huge_allocs", 0)
    total_anon_bytes       = mem.get("total_mmap_bytes", 0)
    memory_p = MemoryProfile(
        scratchpad_allocs      = scratchpad_allocs,
        scratchpad_huge_allocs = scratchpad_huge_allocs,
        total_anon_mb          = total_anon_bytes / (1024 * 1024),
        huge_page_requests     = mem.get("huge_page_requests", 0),
        scratchpad_mb          = scratchpad_allocs * 2.0,
        # Stable if scratchpad was allocated and no new large allocs in last window
        working_set_stable = (scratchpad_allocs > 0
                              and temporal.age_seconds > 30
                              and total_anon_bytes > 0),
    )

    # ── Scheduler profile ──────────────────────────────────────────────────
    vol   = sched.get("voluntary_switches",   0)
    invol = sched.get("involuntary_switches", 0)
    total_sw = max(vol + invol, 1)
    sched_p = SchedulerProfile(
        cpu_bound_ratio      = invol / total_sw,
        on_cpu_ns            = sched.get("on_cpu_ns", 0),
        involuntary_switches = invol,
        voluntary_switches   = vol,
    )

    # ── Network profile ────────────────────────────────────────────────────
    net_p = NetworkProfile(
        pool_connections = net.get("mining_pool_hits", 0),
        total_connections= net.get("total_connections", 0),
    )

    return BehaviouralFingerprint(
        pid=pid, comm=comm,
        syscall=syscall_p, parallelism=parallel_p,
        memory=memory_p,   scheduler=sched_p,
        temporal=temporal, network=net_p,
    )


# psutil cache
_procs: dict = {}

def _cpu_percent(pid: int) -> float:
    try:
        import psutil
        if pid not in _procs:
            _procs[pid] = psutil.Process(pid)
        return _procs[pid].cpu_percent(interval=None)
    except Exception:
        _procs.pop(pid, None)
        return 0.0
