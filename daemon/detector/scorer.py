"""
EDDMC - Deterministic Behavioural Scoring Engine

Converts a feature vector into a suspicion score in [0, 100] and maps
it to a confidence tier and recommended mitigation action.

Design: weighted additive scoring with hard-veto rules.
Each feature contributes a partial score when it exceeds a threshold.
A single pool_hits > 0 immediately pushes the score past MEDIUM so that
network-confirmed miners are never under-responded.

Score tiers
-----------
NONE     [0,  20)  - Normal process, no action
LOW      [20, 40)  - Watch; log event
MEDIUM   [40, 60)  - Alert + CPU throttle
HIGH     [60, 80)  - Alert + throttle + network block
CRITICAL [80, 100] - Alert + throttle + block + suspend/kill
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict


# ── Threshold constants ────────────────────────────────────────────────────────

# futex_ratio: >35% of all syscalls being futex is a strong mining signal
FUTEX_THRESH_WEAK   = 0.20
FUTEX_THRESH_STRONG = 0.40

# io_ratio: miners barely do I/O; <2% is suspicious when CPU is also high
IO_RATIO_LOW        = 0.05
IO_RATIO_VERY_LOW   = 0.02

# cpu_bound_ratio: >85% involuntary switches = CPU-bound
CPU_BOUND_WEAK      = 0.75
CPU_BOUND_STRONG    = 0.90

# thread_density relative to CPU count
THREAD_DENSITY_WEAK   = 0.60
THREAD_DENSITY_STRONG = 0.90

# Sustained CPU usage from psutil
CPU_PERCENT_WEAK    = 70.0
CPU_PERCENT_STRONG  = 90.0

# mmap_ratio: scratch-buffer allocation pattern
MMAP_THRESH         = 0.03

# nanosleep: throttling miners sleep ~10% of syscalls; aggressive never sleep
NANOSLEEP_THROTTLE  = 0.08

# Pool connection = automatic escalation floor
POOL_HIT_FLOOR_SCORE = 50.0

# ── Weight table ───────────────────────────────────────────────────────────────
# Each entry: (weight, description)
# Weights are tuned so that a genuine miner at full throttle scores ~85-95
# and a benign CPU-intensive process scores <30.
WEIGHTS = {
    "futex_strong":       22,
    "futex_weak":         10,
    "io_very_low":        12,
    "io_low":              6,
    "cpu_bound_strong":   18,
    "cpu_bound_weak":      8,
    "thread_density_str": 12,
    "thread_density_wk":   6,
    "cpu_percent_strong": 10,
    "cpu_percent_weak":    5,
    "mmap":                5,
    "nanosleep_throttle":  4,
    "pool_hit":           40,   # single pool connection is nearly conclusive
}


@dataclass
class ScoringResult:
    pid:        int
    comm:       str
    score:      float
    confidence: str
    mitigation: str
    reasons:    list[str]
    features:   dict


def score(pid: int, comm: str, features: Dict[str, float]) -> ScoringResult:
    """
    Deterministically scores a process based on its behavioral features.
    Returns a ScoringResult with score, confidence tier, and mitigation action.
    """
    s = 0.0
    reasons = []

    f = features

    # Pool connection check first — can raise floor immediately
    if f["pool_hits"] > 0:
        s += WEIGHTS["pool_hit"]
        reasons.append(f"stratum pool connection detected ({f['pool_hits']} hits)")

    # futex ratio
    if f["futex_ratio"] >= FUTEX_THRESH_STRONG:
        s += WEIGHTS["futex_strong"]
        reasons.append(f"futex_ratio={f['futex_ratio']:.2f} (>={FUTEX_THRESH_STRONG})")
    elif f["futex_ratio"] >= FUTEX_THRESH_WEAK:
        s += WEIGHTS["futex_weak"]
        reasons.append(f"futex_ratio={f['futex_ratio']:.2f} (>={FUTEX_THRESH_WEAK})")

    # io ratio — only penalise when combined with high CPU (avoids FP on idle procs)
    if f["cpu_percent"] >= CPU_PERCENT_WEAK:
        if f["io_ratio"] <= IO_RATIO_VERY_LOW:
            s += WEIGHTS["io_very_low"]
            reasons.append(f"io_ratio={f['io_ratio']:.3f} (very low I/O with high CPU)")
        elif f["io_ratio"] <= IO_RATIO_LOW:
            s += WEIGHTS["io_low"]
            reasons.append(f"io_ratio={f['io_ratio']:.3f} (low I/O with high CPU)")

    # cpu bound ratio
    if f["cpu_bound_ratio"] >= CPU_BOUND_STRONG:
        s += WEIGHTS["cpu_bound_strong"]
        reasons.append(f"cpu_bound_ratio={f['cpu_bound_ratio']:.2f} (never yields)")
    elif f["cpu_bound_ratio"] >= CPU_BOUND_WEAK:
        s += WEIGHTS["cpu_bound_weak"]
        reasons.append(f"cpu_bound_ratio={f['cpu_bound_ratio']:.2f} (rarely yields)")

    # thread density
    if f["thread_density"] >= THREAD_DENSITY_STRONG:
        s += WEIGHTS["thread_density_str"]
        reasons.append(
            f"thread_density={f['thread_density']:.2f} "
            f"({f['thread_count']} threads ≈ CPU count)"
        )
    elif f["thread_density"] >= THREAD_DENSITY_WEAK:
        s += WEIGHTS["thread_density_wk"]
        reasons.append(f"thread_density={f['thread_density']:.2f}")

    # cpu percent
    if f["cpu_percent"] >= CPU_PERCENT_STRONG:
        s += WEIGHTS["cpu_percent_strong"]
        reasons.append(f"cpu_percent={f['cpu_percent']:.1f}%")
    elif f["cpu_percent"] >= CPU_PERCENT_WEAK:
        s += WEIGHTS["cpu_percent_weak"]
        reasons.append(f"cpu_percent={f['cpu_percent']:.1f}%")

    # mmap (scratch buffers)
    if f["mmap_ratio"] >= MMAP_THRESH and f["cpu_percent"] >= CPU_PERCENT_WEAK:
        s += WEIGHTS["mmap"]
        reasons.append(f"mmap_ratio={f['mmap_ratio']:.3f}")

    # nanosleep — throttling miners sleep just enough to avoid detection
    if IO_RATIO_VERY_LOW < f["nanosleep_ratio"] <= NANOSLEEP_THROTTLE:
        s += WEIGHTS["nanosleep_throttle"]
        reasons.append(f"nanosleep_ratio={f['nanosleep_ratio']:.3f} (throttling pattern)")

    # Clamp to [0, 100]
    s = min(max(s, 0.0), 100.0)

    confidence, mitigation = _tier(s)

    return ScoringResult(
        pid=pid,
        comm=comm,
        score=round(s, 2),
        confidence=confidence,
        mitigation=mitigation,
        reasons=reasons,
        features=features,
    )


def _tier(score: float) -> tuple[str, str]:
    if score >= 80:
        return "CRITICAL", "TERMINATE"
    if score >= 60:
        return "HIGH",     "BLOCK"
    if score >= 40:
        return "MEDIUM",   "THROTTLE"
    if score >= 20:
        return "LOW",      "ALERT"
    return "NONE", "NONE"
