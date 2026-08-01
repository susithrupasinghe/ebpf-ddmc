# Task: Fix TID attribution in sched_monitor, then verify on ONE track

## Context

You are in the EDDMC repository. `reports/BASELINE_COMPARISON_NOTES.md` established that
`daemon/ebpf/sched_monitor.c` keys `on_cpu_ns` by raw thread ID and deletes the map entry when
a thread exits, so a process whose real work runs on worker threads never has that CPU time
attributed to it. XMRig reads approximately 0.01% CPU while confirmed saturating a core, and a
gcc worker produced a negative delta on a counter that should be monotonic.

This may be worse than a blocked baseline comparison. `evaluation/figures/fig_feature_contribution.png`
shows `cpu_percent`, `cpu_bound_ratio` and `futex_ratio` all contributing **zero** at the peak
tick of a miner running at 99.7% CPU. Those signals should be firing hard: `cpu_high` triggers
at 85% and `cpu_bound_strong` at a 0.92 ratio, both of which a saturated RandomX miner satisfies
comfortably. If the same attribution defect affects the voluntary and involuntary switch
counters in the same `sched_stats` map, several weighted signals may have been structurally
unable to fire for any multi-threaded process throughout the entire evaluation.

The purpose of this task is to find out, cheaply, whether that is true.

## SCOPE BOUNDARY — read before starting

This is a **fix and single-track verification**, not a re-evaluation.

**Do:** fix the attribution defect, re-run **one** XMRig capture, compare before and after.

**Do not:** recapture the benign tracks, recompute the confusion matrix, rebuild the ablation
tables, regenerate figures, or start the baseline comparison. The existing evaluation results
stand as they are and must not be overwritten. Write all new output to
`evaluation/results/postfix/` so nothing existing is touched.

If the fix turns out to be larger than expected, or the verification result is ambiguous, stop
and report rather than expanding scope. A clear negative result delivered today is worth more
than an open-ended re-evaluation.

## Ground rules

- Never invent a value. Trace every figure to a CSV row, a log line, or code you can cite.
- Report an unfavourable outcome plainly. If scores do not improve, that is a real and useful
  finding and it must be stated as such.
- Commit before and after the fix, and record both SHAs.

---

## Step 1 — Establish the full extent of the defect before fixing anything

Read `daemon/ebpf/sched_monitor.c` and `daemon/collectors/sched_collector.py`, and report:

- Which counters live in the affected map. `on_cpu_ns` is confirmed. Determine specifically
  whether **voluntary and involuntary context switch counts** are affected, since
  `cpu_bound_ratio` derives from them and it contributes zero in the figure.
- Whether `futex` counts are affected by the same or a comparable TID keying issue in the
  syscall collector, since `futex_ratio` also contributes zero.
- Exactly when map entries are deleted, and whether any aggregation to TGID happens before
  deletion.

**State plainly which of the 14 weighted signals in `docs/ARTEFACT_INVENTORY.md` could not have
fired correctly for a multi-threaded process.** This list is the single most important output of
this step, and it is worth reporting even if the fix that follows fails.

## Step 2 — Fix the attribution

Aggregate per-thread values to the thread group leader (TGID) so a process accumulates the CPU
time and switch counts of all its threads. Critically, **aggregate on thread exit before the map
entry is deleted**, so exiting threads' contributions are not lost.

Constraints:

- Change attribution only. Do not alter scoring logic, weights, thresholds, floors or tier
  boundaries. This verification is meaningless if the scoring model changes at the same time.
- Handle counter resets and PID reuse so deltas cannot go negative. The negative delta observed
  on the gcc worker must not recur.
- Keep the change minimal and reviewable. Note any performance implication of aggregating in the
  eBPF program versus in user space.

## Step 3 — Verify the fix in isolation, before any scoring run

Confirm the fix works at the telemetry level first, so that a later scoring result cannot be
misread. Run a short multi-threaded CPU-bound workload and confirm:

- Derived CPU utilisation for the process now approximates its true utilisation, validated
  against `psutil` sampled independently, in the manner of
  `evaluation/measure_mitigation_effect_v2.py`.
- Deltas are monotonic, with no negative values.
- Switch counts are non-zero and plausible for a saturated process.

**If this step fails, stop and report.** Do not proceed to scoring.

## Step 4 — Single-track scoring comparison

Re-run **one** capture only: XMRig, configuration matching `xmrig_ground_truth_1M.csv` as closely
as the environment allows, approximately 300 seconds, `dry_run: false` via a scoped `--config`
override exactly as used for the Task 7 measurement, with `local.yaml` left untouched.

Ensure a clean daemon: exactly one instance, no systemd instance running, no stale process-store
state, and no orphaned miner from a previous run. All three of these have caused contamination
in previous sessions.

Write the capture to `evaluation/results/postfix/xmrig_postfix.csv` and report:

| | Pre-fix (recorded) | Post-fix (this run) |
|---|---|---|
| Peak score | 45.0 | |
| Peak tier | MEDIUM | |
| Time to LOW | 77.2s | |
| Time to MEDIUM | 104.0s | |
| Time to HIGH | never | |
| Time to CRITICAL | never | |
| Mitigation applied | THROTTLE | |

Then run `evaluation/replay_scorer.py` against the new capture and produce a per-feature
contribution breakdown at the peak tick, in the same form as the existing ablation. **Report
which specific features now contribute non-zero that previously contributed zero, with their
values.** This is the evidence that identifies what the defect was suppressing.

## Step 5 — Report the three consequences

Answer each directly:

1. **Does the weighted sum now reach HIGH tier at 60 or above, independently of the hard-evidence
   floors?** Pre-fix it was 38 against a floor of 45, so the floor was carrying detection. If the
   weighted model now reaches MEDIUM or HIGH on its own, the ablation finding that the scratchpad
   signature dominates needs qualifying, because several signals were absent rather than
   redundant.
2. **Is CRITICAL tier reachable?** Report the peak score and the arithmetic gap remaining to 80.
   If a live pool connection would close that gap, say so and state by how much, but do not run
   a mock stratum experiment in this task.
3. **Would the fingerprint confirmation gate now be satisfiable?** Check all five gate conditions
   in `daemon/fingerprint/assessor.py` against the post-fix peak observation and report which
   pass and which fail.

## Step 6 — False-positive safety check

A fix that raises miner scores may also raise benign scores, and your strongest result is zero
false positives. **Do not recapture the benign tracks.** Instead, replay the existing benign CSVs
through the post-fix scorer offline and report whether any observation would now reach LOW or
MEDIUM.

If the raw counters in those CSVs were themselves affected by the defect, the replay may not be
meaningful. Say so rather than reporting a falsely reassuring result. In that case, run one short
gcc or OpenSSL capture under the fixed collector purely as a false-positive sanity check, and
label it clearly as a spot check rather than a re-evaluation.

---

## Report back

`reports/POSTFIX_VERIFICATION.md`, opening with a direct answer to this question:

**Did the fix change the peak score and tier, and if so, to what?**

Then cover: the Step 1 list of affected signals, what the fix changed, the Step 3 telemetry
validation, the Step 4 comparison table and feature breakdown, the Step 5 answers, and the
Step 6 false-positive check. Finish with your own assessment of whether a full re-evaluation is
now justified, given what the single track showed.