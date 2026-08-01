#!/usr/bin/env python3
"""
EDDMC Evaluation — offline scorer replay (Chapter 6 data extraction, Task 1).

Rebuilds a BehaviouralFingerprint from one results_capture.py CSV row and
re-scores it through the REAL, unmodified daemon.detector.fingerprint /
daemon.detector.scorer pipeline -- not a reimplementation of the scoring
formula. This is what makes the feature-contribution trace and the
leave-one-out ablation defensible: every number traces back to the actual
production code being run against historically captured raw counters.

The one field results_capture.py's CSV schema does NOT retain is
`parallelism.cpu_percent` (fingerprint.py's `_cpu_percent()` samples it
live from psutil at scoring time -- it was never persisted). This module
recovers it where possible by parsing the daemon's own "reasons" text,
which embeds the exact live cpu_percent value for any tick where a
cpu_percent-gated branch fired (see scorer.py's `futex dominance ... at
{cpu:.0f}% CPU` / `sustained CPU {cpu:.0f}%` reason strings). Where no such
branch fired, cpu_percent is genuinely unrecoverable for that tick and this
module defaults it to 0.0 -- which is safe, not a guess: every cpu_percent-
gated `s +=` branch in scorer.py also appends a matching reason string, so
if that reason is absent, the branch did not fire live regardless of the
true cpu_percent value, and defaulting to 0.0 cannot manufacture a branch
firing that didn't really happen. It can only under-count a branch that
truly fired but left no textual trace -- which cannot occur, by
construction of scorer.py's code (every `s += W[...]` has a paired
`reasons.append(...)` immediately after it).

Validation: `replay_row()` recomputes the score and asserts it matches the
CSV's own recorded `score` column (rounding aside) -- if it doesn't, that
row's cpu_percent could not be safely defaulted and is flagged rather than
silently reported as ablation-ready data.
"""

from __future__ import annotations
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from daemon.detector.fingerprint import build as build_fingerprint, TemporalProfile
from daemon.detector.scorer import Scorer, DEFAULT_WEIGHTS

_CPU_PATTERNS = [
    re.compile(r"at (\d+)% CPU"),
    re.compile(r"sustained CPU (\d+)%"),
]


def parse_cpu_percent(reasons: str) -> float | None:
    """Recover cpu_percent from the daemon's own reason text, if present."""
    for pat in _CPU_PATTERNS:
        m = pat.search(reasons or "")
        if m:
            return float(m.group(1))
    return None


def row_to_proc_data(row: dict) -> dict:
    """Invert results_capture.py's `_flatten()` back into the nested dict
    shape `fingerprint.build()` expects."""
    return {
        "comm": row.get("comm", ""),
        "syscall_counts": {
            "total":     int(float(row["total_syscalls"])),
            "futex":     int(float(row["futex"])),
            "mmap":      int(float(row["mmap"])),
            "mprotect":  int(float(row["mprotect"])),
            "clone":     int(float(row["clone"])),
            "nanosleep": int(float(row["nanosleep"])),
            "read":      int(float(row["read"])),
            "write":     int(float(row["write"])),
        },
        "sched": {
            "thread_count":         int(float(row["thread_count"])),
            "on_cpu_ns":            int(float(row["on_cpu_ns"])),
            "voluntary_switches":   int(float(row["voluntary_switches"])),
            "involuntary_switches": int(float(row["involuntary_switches"])),
        },
        "net": {
            "mining_pool_hits":  int(float(row["mining_pool_hits"])),
            "total_connections": int(float(row["total_connections"])),
        },
        "mem": {
            "total_mmap_bytes":       int(float(row["total_mmap_bytes"])),
            "scratchpad_allocs":      int(float(row["scratchpad_allocs"])),
            "huge_page_requests":     int(float(row["huge_page_requests"])),
            # NOTE: the CSV schema tracks `scratchpad_allocs` (size-match
            # alone) but has NO separate column for the joint
            # size-AND-hugepage `scratchpad_huge_allocs` the live scorer
            # actually floors on (fingerprint.py reads
            # mem["scratchpad_huge_allocs"], a key results_capture.py never
            # wrote). See replay_row()'s reconstruction rule below.
        },
    }


def reconstruct_scratchpad_huge_allocs(row: dict) -> int:
    """
    The CSV never captured `scratchpad_huge_allocs` (the joint size+hugepage
    signal the scorer actually floors on) as its own column -- only the
    weaker `scratchpad_allocs` (size alone) and `huge_page_requests` (huge
    pages requested at all, not necessarily on a scratchpad-sized region).
    Recovered the same way as cpu_percent: the daemon's own reasons text
    says explicitly "RandomX signature: N x 2MB scratchpad allocation(s)
    backed by huge pages" whenever scratchpad_huge_allocs > 0 -- parse N
    from there. Absence of that exact phrase means scratchpad_huge_allocs
    was 0 at that tick (the joint condition did not hold), by the same
    every-branch-has-a-reason argument as parse_cpu_percent.
    """
    m = re.search(r"RandomX signature: (\d+) . 2MB scratchpad", row.get("reasons", "") or "")
    return int(m.group(1)) if m else 0



# The scratchpad hard-evidence floor gates on `cpu_percent >= 1.0` as a
# deliberately low "not fully idle/dead" bar (scorer.py's own docstring) --
# it is NOT accompanied by a reasons.append() the way every `s += W[...]`
# branch is, since `s = max(s, floor)` is applied after the weighted sum,
# unconditionally on the raw evidence. That means the "every fired branch
# leaves a textual trace" argument this module otherwise relies on does
# NOT cover the floor. A flat 0.0 default for unrecovered cpu_percent is
# therefore unsafe here specifically: it would silently suppress a floor
# that really applied live, understating the replayed score. Fixed at 2.0
# instead when cpu_percent can't be recovered and the process shows any
# on-CPU progress since its previous captured tick (on_cpu_ns increased) --
# clears the floor's >=1.0 bar while staying far below every other
# cpu_percent-gated threshold in scorer.py (50/70/85), so it cannot
# manufacture a higher-threshold branch firing that didn't happen live.
_ALIVE_DEFAULT_CPU_PERCENT = 2.0


def replay_row(row: dict, weight_overrides: dict | None = None, prev_on_cpu_ns: int | None = None):
    """
    Rebuild the fingerprint for one CSV row and score it through the real
    pipeline. `weight_overrides` is passed straight to Scorer's config for
    leave-one-out ablation (e.g. {"futex_strong": 0, "futex_moderate": 0}).
    `prev_on_cpu_ns` is the same PID's `on_cpu_ns` at the previous captured
    tick (None for a track's first row) -- used only to pick a safe
    cpu_percent default when it can't be recovered from the reasons text;
    see `_ALIVE_DEFAULT_CPU_PERCENT` above.
    Returns (ScoringResult, cpu_percent_used, cpu_percent_recovered_exactly).
    """
    proc_data = row_to_proc_data(row)
    temporal = TemporalProfile(
        first_seen=0.0,
        suspicious_ticks=int(float(row.get("ticks", 0))),
        age_seconds=float(row["elapsed_s"]),
    )
    fp = build_fingerprint(int(float(row["pid"])), proc_data, temporal)

    cpu_recovered = parse_cpu_percent(row.get("reasons", ""))
    if cpu_recovered is not None:
        fp.parallelism.cpu_percent = cpu_recovered
    else:
        on_cpu_ns = int(float(row["on_cpu_ns"]))
        presumed_alive = prev_on_cpu_ns is None or on_cpu_ns > prev_on_cpu_ns
        fp.parallelism.cpu_percent = _ALIVE_DEFAULT_CPU_PERCENT if presumed_alive else 0.0

    fp.memory.scratchpad_huge_allocs = reconstruct_scratchpad_huge_allocs(row)

    cfg = {}
    if weight_overrides:
        cfg["weights"] = weight_overrides
    scorer = Scorer(cfg)
    result = scorer.score(fp)
    return result, fp.parallelism.cpu_percent, cpu_recovered is not None


def replay_track(rows: list[dict], weight_overrides: dict | None = None):
    """Replay every row of one track in order, threading on_cpu_ns history
    through so replay_row() can pick a safe cpu_percent default per-tick."""
    out = []
    prev_on_cpu_ns = None
    for row in rows:
        result, cpu_used, cpu_exact = replay_row(row, weight_overrides, prev_on_cpu_ns)
        out.append((row, result, cpu_used, cpu_exact))
        prev_on_cpu_ns = int(float(row["on_cpu_ns"]))
    return out


# Dimension groupings for leave-one-out ablation -- grouped rather than
# per-weight-key because several keys are mutually exclusive elif branches
# in scorer.py (at most one of a pair can ever contribute at a given tick),
# so ablating them individually would produce redundant all-zero rows.
ABLATION_GROUPS = {
    "futex (syscall barrier signal)":      ["futex_strong", "futex_moderate"],
    "compute-pure (low I/O + high CPU)":   ["compute_pure"],
    "thread saturation":                   ["thread_full_sat", "thread_partial_sat"],
    "sustained high CPU%":                 ["cpu_high"],
    "RandomX scratchpad (weighted term)":  ["scratchpad_exact", "scratchpad_weak"],
    "huge pages requested":                ["huge_pages"],
    "scheduler CPU-boundedness":           ["cpu_bound_strong", "cpu_bound_moderate"],
    "temporal sustained-detection":        ["sustained_medium", "sustained_high"],
    "pool connection (weighted term)":     ["pool_connection"],
}

assert set(k for ks in ABLATION_GROUPS.values() for k in ks) == set(DEFAULT_WEIGHTS.keys()), \
    "ABLATION_GROUPS must cover every key in DEFAULT_WEIGHTS exactly once"
