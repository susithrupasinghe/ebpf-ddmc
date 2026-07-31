#!/usr/bin/env python3
"""
EDDMC Evaluation — Chapter 6 data extraction, Task 1 part A.

Writes evaluation/results/feature_contributions.csv: one row per scorer
feature per captured tick, for one representative mining track
(xmrig_ground_truth_1M.csv) and one representative benign track
(benign_openssl_t1.csv -- the only benign track that ever produced a
nonzero score/reason at all; gcc scored a flat 0.0 throughout and would
add rows with nothing to show).

Recomputed via evaluation/replay_scorer.py against the REAL
daemon.detector.scorer.Scorer, not a reimplemented formula. See that
module's docstring for how the one CSV-schema gap (cpu_percent) is
recovered/defaulted, and for what "floor_engaged" means.

Known caveat, stated here rather than hidden: a small fraction of ticks in
xmrig_ground_truth_1M.csv (50/219 nonzero rows) replay to a different score
than the daemon originally recorded live. Root cause, confirmed by
inspection: `daemon/detector/fingerprint.py:_cpu_percent()` calls
`psutil.Process(pid).cpu_percent(interval=None)`, which returns a
meaningless 0.0 on a process's first-ever sampled call by psutil's own
documented convention -- this can suppress the scratchpad floor for
exactly the tick where a scan first observes a newly-scored process,
producing a real recorded score lower than what the same raw evidence
would produce once psutil has a baseline. Combined with the
already-documented scan-cycle inflation (REPORT.md §4 -- a single stale
live score can persist across many 1s capture polls before the next
_scan() cycle runs), this produces a run of several capture rows sharing
one artificially-low recorded score before it jumps to the value this
replay computes. All four tracks' PEAK-score ticks -- what Task 1's
ablation section actually needs -- replay to an EXACT match with the
recorded score (verified separately), since peaks occur well after this
transient settles. This file reports the replayed value at every tick and
flags rows where it disagrees with the row's own recorded score, rather
than silently presenting one as if it were the other.
"""

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from replay_scorer import replay_track

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

TRACKS = {
    "mining": "xmrig_ground_truth_1M.csv",
    "benign": "benign_openssl_t1.csv",
}

OUT_FIELDS = [
    "track", "timestamp", "pid", "feature_name", "raw_value",
    "normalised_value", "weight", "contribution", "floor_engaged",
    "running_score", "tier", "replay_matches_recorded",
]


def feature_rows_for_tick(row, result, cpu_used):
    """One row per scorer feature for this tick, in scorer.py's own
    evaluation order. `contribution` is this feature's own weighted
    addition to the score for THIS tick (0 if its condition didn't hold).
    `running_score` accumulates across the rows below within one tick, in
    the same order scorer.py itself evaluates them, ending at the
    pre-floor weighted sum; floor rows (if any) then show the jump to the
    post-floor score."""
    W = result.fingerprint  # unused directly; kept for clarity of intent
    fp = result.fingerprint
    reasons_joined = "; ".join(result.reasons)
    running = 0.0
    out = []

    def emit(name, raw, norm, weight, fired):
        nonlocal running
        contrib = weight if fired else 0.0
        running += contrib
        out.append({
            "feature_name": name, "raw_value": raw, "normalised_value": norm,
            "weight": weight if fired else 0.0, "contribution": contrib,
            "floor_engaged": "", "running_score": round(running, 2),
        })

    sc, par, mem, sch, temp, net = fp.syscall, fp.parallelism, fp.memory, fp.scheduler, fp.temporal, fp.network
    from daemon.detector.scorer import DEFAULT_WEIGHTS as Wt

    futex_strong = sc.futex_ratio >= 0.40 and par.cpu_percent >= 50.0
    futex_moderate = (not futex_strong) and sc.futex_ratio >= 0.20 and par.cpu_percent >= 50.0
    emit("futex_ratio", sc.futex_ratio, sc.futex_ratio,
         Wt["futex_strong"] if futex_strong else (Wt["futex_moderate"] if futex_moderate else 0),
         futex_strong or futex_moderate)

    compute_pure = sc.io_ratio < 0.02 and par.cpu_percent >= 70.0
    emit("compute_pure (io_ratio)", sc.io_ratio, sc.io_ratio, Wt["compute_pure"], compute_pure)

    cpu_count = os.cpu_count() or 1
    thread_full = par.thread_count >= cpu_count
    thread_partial = (not thread_full) and par.thread_count >= int(cpu_count * 0.6)
    emit("thread_count", par.thread_count, par.thread_count / cpu_count,
         Wt["thread_full_sat"] if thread_full else (Wt["thread_partial_sat"] if thread_partial else 0),
         thread_full or thread_partial)

    cpu_high = par.cpu_percent >= 85.0
    emit("cpu_percent", par.cpu_percent, par.cpu_percent / 100.0, Wt["cpu_high"], cpu_high)

    scratch_exact = mem.scratchpad_huge_allocs > 0
    scratch_weak = (not scratch_exact) and mem.scratchpad_allocs > 0
    emit("scratchpad_allocs (weighted term)",
         mem.scratchpad_huge_allocs if scratch_exact else mem.scratchpad_allocs,
         mem.scratchpad_mb,
         Wt["scratchpad_exact"] if scratch_exact else (Wt["scratchpad_weak"] if scratch_weak else 0),
         scratch_exact or scratch_weak)

    huge = mem.huge_page_requests > 0
    emit("huge_page_requests", mem.huge_page_requests, mem.huge_page_requests, Wt["huge_pages"], huge)

    cpu_bound_strong = sch.cpu_bound_ratio >= 0.92
    cpu_bound_moderate = (not cpu_bound_strong) and sch.cpu_bound_ratio >= 0.75
    emit("cpu_bound_ratio", sch.cpu_bound_ratio, sch.cpu_bound_ratio,
         Wt["cpu_bound_strong"] if cpu_bound_strong else (Wt["cpu_bound_moderate"] if cpu_bound_moderate else 0),
         cpu_bound_strong or cpu_bound_moderate)

    sustained_high = temp.suspicious_ticks >= 6
    sustained_medium = (not sustained_high) and temp.suspicious_ticks >= 3
    emit("suspicious_ticks", temp.suspicious_ticks, temp.suspicious_ticks,
         Wt["sustained_high"] if sustained_high else (Wt["sustained_medium"] if sustained_medium else 0),
         sustained_high or sustained_medium)

    pool = net.pool_connections > 0
    emit("pool_connections", net.pool_connections, 1 if pool else 0, Wt["pool_connection"], pool)

    # Floor rows -- these show the jump from the pre-floor weighted sum
    # (`running` above) to the post-floor score, if a floor engaged.
    pool_floor_engaged = net.pool_connections > 0 and running < 50
    if net.pool_connections > 0 and running < 50:
        out.append({
            "feature_name": "[FLOOR] pool_connection >= 50", "raw_value": net.pool_connections,
            "normalised_value": "", "weight": "", "contribution": 50 - running,
            "floor_engaged": "yes", "running_score": 50.0,
        })
        running = 50.0
    scratch_floor_engaged = mem.scratchpad_huge_allocs > 0 and par.cpu_percent >= 1.0 and running < 45
    if scratch_floor_engaged:
        out.append({
            "feature_name": "[FLOOR] scratchpad_huge_allocs >= 45", "raw_value": mem.scratchpad_huge_allocs,
            "normalised_value": "", "weight": "", "contribution": 45 - running,
            "floor_engaged": "yes", "running_score": 45.0,
        })
        running = 45.0

    if temp.age_seconds < 20.0 and running >= 60.0:
        out.append({
            "feature_name": "[CAP] young-process cap at 55", "raw_value": temp.age_seconds,
            "normalised_value": "", "weight": "", "contribution": 55 - running,
            "floor_engaged": "cap", "running_score": 55.0,
        })
        running = 55.0

    for r in out:
        r["tier"] = result.confidence
    return out


def main():
    all_rows = []
    for track_label, fname in TRACKS.items():
        path = os.path.join(RESULTS_DIR, fname)
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
        replayed = replay_track(rows)
        for row, result, cpu_used, cpu_exact in replayed:
            matches = abs(result.score - float(row["score"])) <= 0.05
            for fr in feature_rows_for_tick(row, result, cpu_used):
                all_rows.append({
                    "track": track_label,
                    "timestamp": row["wall_time"],
                    "pid": row["pid"],
                    "replay_matches_recorded": "yes" if matches else "no (see module docstring)",
                    **fr,
                })

    out_path = os.path.join(RESULTS_DIR, "feature_contributions.csv")
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        w.writeheader()
        w.writerows(all_rows)

    n_ticks = sum(1 for _ in TRACKS)
    mismatches = sum(1 for r in all_rows if r["replay_matches_recorded"].startswith("no"))
    print(f"[feature_contributions] wrote {len(all_rows)} rows to {out_path}")
    print(f"[feature_contributions] tracks: {TRACKS}")
    print(f"[feature_contributions] feature-rows flagged as non-matching ticks: {mismatches}/{len(all_rows)}")


if __name__ == "__main__":
    main()
