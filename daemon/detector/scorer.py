"""
EDDMC - Behavioural Fingerprint Scorer

Converts a BehaviouralFingerprint into a suspicion score [0, 100] using
a weighted multi-dimensional scoring model.

Design principles
-----------------
1. SPECIFICITY OVER SENSITIVITY
   Each feature threshold is set to capture cryptomining behaviour specifically,
   not just any high-resource process.  A video encoder scores <20; a miner scores >70.

2. TEMPORAL GATING
   The score is penalised for youth and rewarded for sustained detection.
   A process must maintain suspicion across multiple scan windows before
   high-confidence mitigation is applied.  This eliminates false positives
   from bursty legitimate workloads (builds, renders, ML training).

3. HARD EVIDENCE ESCALATION
   Some signals are near-conclusive regardless of other features:
   - Pool connection (stratum port) → score floor at 50
   - RandomX scratchpad (N × 2MB) + high CPU → score floor at 45
   These cannot be offset by low scores elsewhere.

Score tiers
-----------
NONE     [0,  20)  → ignore
LOW      [20, 40)  → log alert only
MEDIUM   [40, 60)  → log + CPU throttle (cgroup)
HIGH     [60, 80)  → + network block (iptables)
CRITICAL [80,100]  → + suspend; auto-kill if enabled
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List
import math

from daemon.detector.fingerprint import BehaviouralFingerprint


# ── Weights ────────────────────────────────────────────────────────────────────
# Max total from all non-network features ≈ 65; pool_connection adds up to 40.
# A genuine full-speed miner with pool connection should score 85-100.
# A genuine miner without network (solo/air-gapped) should score 60-75.
# A benign CPU-intensive process (compile, ML) should score 10-30.

W = {
    # Syscall dimension (max 28)
    "futex_strong":        18,   # futex_ratio >= 0.40
    "futex_moderate":       9,   # futex_ratio >= 0.20
    "compute_pure":        10,   # io_ratio < 0.02 AND cpu > 70%

    # Parallelism dimension (max 18)
    "thread_full_sat":     12,   # thread_count >= cpu_count
    "thread_partial_sat":   6,   # thread_count >= 0.6 × cpu_count
    "cpu_high":             6,   # cpu_percent >= 85%

    # Memory dimension (max 20)
    "scratchpad_exact":    15,   # N × 2MB allocs > 0  (RandomX signature)
    "huge_pages":           5,   # MAP_HUGETLB requested

    # Scheduler dimension (max 16)
    "cpu_bound_strong":    12,   # involuntary_ratio >= 0.92
    "cpu_bound_moderate":   6,   # involuntary_ratio >= 0.75

    # Temporal dimension (max 14)
    "sustained_medium":     7,   # suspicious_ticks >= 3 (15 s)
    "sustained_high":      14,   # suspicious_ticks >= 6 (30 s)

    # Network dimension (hard-evidence bonus, max 40)
    "pool_connection":     40,   # confirmed stratum port TCP connection
}

# Hard-evidence score floors — applied AFTER weighted sum
POOL_FLOOR       = 50   # confirmed pool connection → never below MEDIUM
SCRATCHPAD_FLOOR = 45   # RandomX memory + high CPU → never below MEDIUM


@dataclass
class ScoringResult:
    pid:          int
    comm:         str
    score:        float
    confidence:   str
    mitigation:   str
    reasons:      List[str]
    fingerprint:  BehaviouralFingerprint


def score(fp: BehaviouralFingerprint) -> ScoringResult:
    s       = 0.0
    reasons = []

    sc    = fp.syscall
    par   = fp.parallelism
    mem   = fp.memory
    sch   = fp.scheduler
    temp  = fp.temporal
    net   = fp.network

    # ── 1. Syscall fingerprint ─────────────────────────────────────────────
    if sc.futex_ratio >= 0.40:
        s += W["futex_strong"]
        reasons.append(f"futex dominance {sc.futex_ratio:.0%} of all syscalls (strong mining signal)")
    elif sc.futex_ratio >= 0.20:
        s += W["futex_moderate"]
        reasons.append(f"elevated futex ratio {sc.futex_ratio:.0%}")

    if sc.io_ratio < 0.02 and par.cpu_percent >= 70.0:
        s += W["compute_pure"]
        reasons.append(
            f"compute-pure: only {sc.io_ratio:.1%} I/O syscalls at {par.cpu_percent:.0f}% CPU"
        )

    # ── 2. Parallelism fingerprint ─────────────────────────────────────────
    import os
    cpu_count = os.cpu_count() or 1

    if par.thread_count >= cpu_count:
        s += W["thread_full_sat"]
        reasons.append(
            f"thread saturation: {par.thread_count} threads = {cpu_count} logical CPUs"
        )
    elif par.thread_count >= int(cpu_count * 0.6):
        s += W["thread_partial_sat"]
        reasons.append(
            f"partial thread saturation: {par.thread_count}/{cpu_count} CPUs"
        )

    if par.cpu_percent >= 85.0:
        s += W["cpu_high"]
        reasons.append(f"sustained CPU {par.cpu_percent:.0f}%")

    # ── 3. Memory fingerprint (RandomX-specific) ───────────────────────────
    if mem.scratchpad_allocs > 0:
        s += W["scratchpad_exact"]
        reasons.append(
            f"RandomX signature: {mem.scratchpad_allocs} × 2MB scratchpad allocation(s) "
            f"({mem.scratchpad_mb:.0f} MB total)"
        )
    if mem.huge_page_requests > 0:
        s += W["huge_pages"]
        reasons.append(f"MAP_HUGETLB requested ({mem.huge_page_requests} times)")

    # ── 4. Scheduler fingerprint ───────────────────────────────────────────
    if sch.cpu_bound_ratio >= 0.92:
        s += W["cpu_bound_strong"]
        reasons.append(
            f"CPU-bound: {sch.cpu_bound_ratio:.0%} involuntary preemptions "
            f"(never yields voluntarily)"
        )
    elif sch.cpu_bound_ratio >= 0.75:
        s += W["cpu_bound_moderate"]
        reasons.append(f"mostly CPU-bound: {sch.cpu_bound_ratio:.0%} involuntary preemptions")

    # ── 5. Temporal fingerprint ────────────────────────────────────────────
    if temp.suspicious_ticks >= 6:
        s += W["sustained_high"]
        reasons.append(
            f"sustained detection: {temp.suspicious_ticks} consecutive scan windows "
            f"(~{temp.suspicious_ticks * 5}s) — rules out bursty legitimate workloads"
        )
    elif temp.suspicious_ticks >= 3:
        s += W["sustained_medium"]
        reasons.append(
            f"persistent suspicion: {temp.suspicious_ticks} consecutive windows"
        )

    # ── 6. Network fingerprint (hard evidence) ─────────────────────────────
    if net.pool_connections > 0:
        s += W["pool_connection"]
        reasons.append(
            f"stratum pool connection confirmed ({net.pool_connections} hit(s)) — "
            f"near-conclusive cryptomining evidence"
        )

    # ── Apply hard-evidence floors ─────────────────────────────────────────
    if net.pool_connections > 0:
        s = max(s, POOL_FLOOR)
    if mem.scratchpad_allocs > 0 and par.cpu_percent >= 70.0:
        s = max(s, SCRATCHPAD_FLOOR)

    # ── Temporal penalty for young processes ───────────────────────────────
    # Don't escalate to HIGH/CRITICAL until we've observed the process for at
    # least 20 seconds — prevents false positives from startup bursts.
    if temp.age_seconds < 20.0 and s >= 60.0:
        s = min(s, 55.0)
        reasons.append("(score capped: process too young for CRITICAL/HIGH escalation)")

    s = min(max(s, 0.0), 100.0)
    confidence, mitigation = _tier(s)

    return ScoringResult(
        pid=fp.pid,
        comm=fp.comm,
        score=round(s, 2),
        confidence=confidence,
        mitigation=mitigation,
        reasons=reasons,
        fingerprint=fp,
    )


def _tier(s: float) -> tuple[str, str]:
    if s >= 80: return "CRITICAL", "TERMINATE"
    if s >= 60: return "HIGH",     "BLOCK"
    if s >= 40: return "MEDIUM",   "THROTTLE"
    if s >= 20: return "LOW",      "ALERT"
    return "NONE", "NONE"
