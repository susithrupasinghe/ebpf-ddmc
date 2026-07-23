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
   - RandomX scratchpad (N × 2MB) *co-occurring with MAP_HUGETLB on the same
     allocation*, process still alive/active → score floor at 45
   These cannot be offset by low scores elsewhere. Note the scratchpad floor
   requires the *joint* size-and-hugepage match, not size alone: a bare
   exact-2MB-multiple allocation is not floor-eligible, since 2MB is also
   the standard Linux transparent-huge-page size and legitimate software
   that merely aligns to it (observed in practice: fwupd, Chromium/
   Electron's allocator) would otherwise floor the score too. Real RandomX
   requests huge pages *for* its scratchpad specifically; that combination
   is what makes the signal near-conclusive, not the size in isolation.
   The floor's CPU-activity check is deliberately a low bar (>=1%), not a
   high one -- it only excludes a fully idle/dead entry, since EDDMC's own
   mitigation (cgroup CPU quotas as low as 5%) would otherwise suppress the
   floor for a process it is *actively and successfully* throttling.

4. CPU-GATED SYSCALL SIGNALS
   futex ratio is only credited when the process is also CPU-intensive
   (>=50%) in the same window. High futex ratio alone is common in any
   lock/condvar-heavy multithreaded runtime (V8, Chromium's Mojo IPC, the
   JVM) even while mostly idle; a real miner's futex traffic is a barrier
   between hash rounds on threads that are simultaneously CPU-saturated.

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
import os

from daemon.detector.fingerprint import BehaviouralFingerprint


# ── Default weights ──────────────────────────────────────────────────────────
# Used for any key not present in `detection.weights` in the daemon config, so
# a partial override in YAML doesn't require repeating every other weight.
# Max total from all non-network features ≈ 65; pool_connection adds up to 40.
# A genuine full-speed miner with pool connection should score 85-100.
# A genuine miner without network (solo/air-gapped) should score 60-75.
# A benign CPU-intensive process (compile, ML) should score 10-30.

DEFAULT_WEIGHTS = {
    # Syscall dimension (max 28)
    "futex_strong":        18,   # futex_ratio >= 0.40
    "futex_moderate":       9,   # futex_ratio >= 0.20
    "compute_pure":        10,   # io_ratio < 0.02 AND cpu > 70%

    # Parallelism dimension (max 18)
    "thread_full_sat":     12,   # thread_count >= cpu_count
    "thread_partial_sat":   6,   # thread_count >= 0.6 × cpu_count
    "cpu_high":             6,   # cpu_percent >= 85%

    # Memory dimension (max 23)
    "scratchpad_exact":    15,   # N × 2MB allocs AND MAP_HUGETLB on the SAME allocation (strong RandomX signature)
    "scratchpad_weak":      3,   # N × 2MB allocs alone, no huge-page flag (weak -- widely shared with non-mining allocators, see scorer docstring)
    "huge_pages":           5,   # MAP_HUGETLB requested (any size, not necessarily scratchpad-sized)

    # Scheduler dimension (max 16)
    "cpu_bound_strong":    12,   # involuntary_ratio >= 0.92
    "cpu_bound_moderate":   6,   # involuntary_ratio >= 0.75

    # Temporal dimension (max 14)
    "sustained_medium":     7,   # suspicious_ticks >= 3 (15 s)
    "sustained_high":      14,   # suspicious_ticks >= 6 (30 s)

    # Network dimension (hard-evidence bonus, max 40)
    "pool_connection":     40,   # confirmed stratum port TCP connection
}

# Hard-evidence score floors — applied AFTER the weighted sum
DEFAULT_POOL_FLOOR       = 50   # confirmed pool connection → never below MEDIUM
DEFAULT_SCRATCHPAD_FLOOR = 45   # RandomX memory + high CPU → never below MEDIUM

# Tier boundaries — keys match `detection.*` in defaults.yaml
DEFAULT_TIER_BOUNDS = {
    "alert_threshold":     20,
    "throttle_threshold":  40,
    "block_threshold":     60,
    "terminate_threshold": 80,
}

_TIER_LABELS = [
    # (config key, min score, confidence, mitigation)
    ("terminate_threshold", "CRITICAL", "TERMINATE"),
    ("block_threshold",     "HIGH",     "BLOCK"),
    ("throttle_threshold",  "MEDIUM",   "THROTTLE"),
    ("alert_threshold",     "LOW",      "ALERT"),
]


@dataclass
class ScoringResult:
    pid:          int
    comm:         str
    score:        float
    confidence:   str
    mitigation:   str
    reasons:      List[str]
    fingerprint:  BehaviouralFingerprint


class Scorer:
    """
    Converts a BehaviouralFingerprint into a suspicion score [0, 100] using a
    weighted multi-dimensional scoring model.

    Weights, hard-evidence floors, and tier boundaries all come from
    `detection:` in the daemon config (falling back to the defaults above for
    any key it omits) so administrators can retune sensitivity for their
    environment without touching code — see `update()` for live retuning.
    """

    def __init__(self, detection_cfg: dict | None = None):
        self._apply_config(detection_cfg or {})

    def update(self, detection_cfg: dict):
        """Apply a new set of weights/floors/thresholds to this live instance (no restart needed)."""
        self._apply_config(detection_cfg)

    def _apply_config(self, cfg: dict):
        self.weights = {**DEFAULT_WEIGHTS, **(cfg.get("weights") or {})}
        self.pool_floor = cfg.get("pool_floor", DEFAULT_POOL_FLOOR)
        self.scratchpad_floor = cfg.get("scratchpad_floor", DEFAULT_SCRATCHPAD_FLOOR)
        self.tier_bounds = {
            k: cfg.get(k, default) for k, default in DEFAULT_TIER_BOUNDS.items()
        }

    def score(self, fp: BehaviouralFingerprint) -> ScoringResult:
        W = self.weights
        s       = 0.0
        reasons = []

        sc    = fp.syscall
        par   = fp.parallelism
        mem   = fp.memory
        sch   = fp.scheduler
        temp  = fp.temporal
        net   = fp.network

        # ── 1. Syscall fingerprint ─────────────────────────────────────────
        # Futex dominance is gated on simultaneous CPU intensity. High futex
        # ratio alone is shared with any lock/condvar-heavy multithreaded
        # runtime (V8, Chromium's Mojo IPC, the JVM) even while doing almost
        # nothing -- observed in practice: an EDDMC Electron renderer sat at
        # 0.5% CPU yet still showed 51% futex ratio. A real miner's futex
        # traffic is a barrier between hash rounds on threads that are
        # simultaneously CPU-saturated, so requiring both together targets
        # the actual mining pattern instead of futex volume in isolation.
        if sc.futex_ratio >= 0.40 and par.cpu_percent >= 50.0:
            s += W["futex_strong"]
            reasons.append(f"futex dominance {sc.futex_ratio:.0%} of all syscalls at {par.cpu_percent:.0f}% CPU (strong mining signal)")
        elif sc.futex_ratio >= 0.20 and par.cpu_percent >= 50.0:
            s += W["futex_moderate"]
            reasons.append(f"elevated futex ratio {sc.futex_ratio:.0%} at {par.cpu_percent:.0f}% CPU")

        if sc.io_ratio < 0.02 and par.cpu_percent >= 70.0:
            s += W["compute_pure"]
            reasons.append(
                f"compute-pure: only {sc.io_ratio:.1%} I/O syscalls at {par.cpu_percent:.0f}% CPU"
            )

        # ── 2. Parallelism fingerprint ─────────────────────────────────────
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

        # ── 3. Memory fingerprint (RandomX-specific) ────────────────────────
        # Strong signal requires the JOINT match (scratchpad-sized AND
        # huge-page-backed on the same allocation) -- a bare size match is
        # scored much lower and never floor-eligible, since size alone is
        # shared with ordinary huge-page-aligned allocators (fwupd,
        # Chromium/Electron) that have nothing to do with RandomX.
        if mem.scratchpad_huge_allocs > 0:
            s += W["scratchpad_exact"]
            reasons.append(
                f"RandomX signature: {mem.scratchpad_huge_allocs} × 2MB scratchpad "
                f"allocation(s) backed by huge pages ({mem.scratchpad_mb:.0f} MB total) "
                f"— strong evidence"
            )
        elif mem.scratchpad_allocs > 0:
            s += W["scratchpad_weak"]
            reasons.append(
                f"{mem.scratchpad_allocs} × 2MB-aligned allocation(s) with no huge-page "
                f"flag — weak signal, commonly shared with non-mining allocators"
            )
        if mem.huge_page_requests > 0:
            s += W["huge_pages"]
            reasons.append(f"MAP_HUGETLB requested ({mem.huge_page_requests} times)")

        # ── 4. Scheduler fingerprint ─────────────────────────────────────────
        if sch.cpu_bound_ratio >= 0.92:
            s += W["cpu_bound_strong"]
            reasons.append(
                f"CPU-bound: {sch.cpu_bound_ratio:.0%} involuntary preemptions "
                f"(never yields voluntarily)"
            )
        elif sch.cpu_bound_ratio >= 0.75:
            s += W["cpu_bound_moderate"]
            reasons.append(f"mostly CPU-bound: {sch.cpu_bound_ratio:.0%} involuntary preemptions")

        # ── 5. Temporal fingerprint ──────────────────────────────────────────
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

        # ── 6. Network fingerprint (hard evidence) ───────────────────────────
        if net.pool_connections > 0:
            s += W["pool_connection"]
            reasons.append(
                f"stratum pool connection confirmed ({net.pool_connections} hit(s)) — "
                f"near-conclusive cryptomining evidence"
            )

        # ── Apply hard-evidence floors ────────────────────────────────────────
        if net.pool_connections > 0:
            s = max(s, self.pool_floor)
        # Floor requires the STRONG (joint scratchpad+hugepage) signal --
        # see the class docstring for why size alone is not floor-eligible.
        # The accompanying CPU-activity check only needs to rule out a fully
        # idle/dead process (not yet pruned) -- it must NOT require a high
        # percentage like the other CPU gates in this method. A confirmed
        # miner that EDDMC has already throttled to a 30%/10%/5% cgroup quota
        # (see mitigation.throttle_quotas) will legitimately report a low
        # cpu_percent on the next scan purely because the mitigation worked;
        # gating the floor on a high threshold turned successful mitigation
        # into evidence the process was no longer suspicious, which caused
        # the confidence tier to flap MEDIUM -> LOW -> MEDIUM every cycle
        # (observed directly: a live XMRig instance oscillated 45/MEDIUM ->
        # 39/LOW within one scan interval while mining continuously).
        if mem.scratchpad_huge_allocs > 0 and par.cpu_percent >= 1.0:
            s = max(s, self.scratchpad_floor)

        # ── Temporal penalty for young processes ─────────────────────────────
        # Don't escalate to HIGH/CRITICAL until we've observed the process for
        # at least 20 seconds — prevents false positives from startup bursts.
        if temp.age_seconds < 20.0 and s >= 60.0:
            s = min(s, 55.0)
            reasons.append("(score capped: process too young for CRITICAL/HIGH escalation)")

        s = min(max(s, 0.0), 100.0)
        confidence, mitigation = self._tier(s)

        return ScoringResult(
            pid=fp.pid,
            comm=fp.comm,
            score=round(s, 2),
            confidence=confidence,
            mitigation=mitigation,
            reasons=reasons,
            fingerprint=fp,
        )

    def _tier(self, s: float) -> tuple[str, str]:
        for key, confidence, mitigation in _TIER_LABELS:
            if s >= self.tier_bounds[key]:
                return confidence, mitigation
        return "NONE", "NONE"
