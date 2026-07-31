# Task: Integrity verification, then baseline comparison

## Context

You are in the EDDMC repository, continuing work documented in
`reports/CH6_DATA_EXTRACTION.md` and `SESSION_SUMMARY_2026-08-01.md`. The dissertation's
Results chapter is about to be written from that data. Two things remain.

The previous session surfaced two environment problems that were found late: an
`eddmc.service` systemd daemon had been running in parallel with a manually started one for
most of the session, and `daemon/config/local.yaml` defaults `mitigation.dry_run` to `true`.
Both were discovered while debugging Task 7. Neither was known during the earlier tasks in
that same session, which means some results may have been produced under conditions nobody
was aware of at the time.

**Part A settles that question. Part B is the remaining data work.** Do Part A first, because
its outcome may change what Part B and the dissertation can claim.

## Ground rules

- Never invent a value. Trace every figure to a CSV row, a log line, or code you can cite.
- Report findings that are inconvenient. If something earlier in this project turns out to be
  wrong, say so plainly. A corrected record is worth more than a clean-looking one.
- Part B is **offline replay only**. Run no new workload, miner, or daemon session for it.
- Commit before each run and record the git SHA.

---

# PART A — Integrity verification

## A1. Determine the blast radius of the duplicate daemon

Establish, as precisely as the logs allow, the window during which two daemon instances were
running concurrently. Then determine which previously reported artefacts were produced inside
that window. Check at minimum:

- The three CLI screenshots from Task 4 (`evaluation/figures/screenshot_*.png`).
- The live re-checks of Claude Code CLI and VS Code recorded in
  `evaluation/results/false_positive_cases.md`.
- Any part of `evaluation/results/mitigation_effect.md` produced before the duplicate was
  stopped.

For each, state: produced inside the window, outside it, or cannot be determined.

**Specific anomaly to check.** `screenshot_eddmc_status.png` reports 889 tracked processes.
Earlier rounds reported 1,144 and approximately 1,912. Determine whether two daemons sharing
one event stream would split or otherwise reduce the tracked-process count. If it would, the
screenshot is showing a degraded state and needs recapturing. If the difference is explained
by something else, such as a shorter uptime at capture time, say so.

## A2. Establish the dry-run history of every mitigation claim

The evaluation record asserts that throttling was applied and independently verified by
reading the cgroup v2 quota from `/sys/fs/cgroup`. If `dry_run: true` was in effect for any of
those runs, no quota would have been written and that verification could not have happened as
described.

Determine, for each mitigation result already reported in `FINAL_EVALUATION_SUMMARY.md`,
`reports/EVALUATION_ROUND2.md` and `reports/CH6_DATA_EXTRACTION.md`, whether the run that
produced it executed with `dry_run` false or true. Use config history, daemon startup logs,
cgroup path existence, or whatever evidence survives.

**Report one of three verdicts per claim:** confirmed enforced, confirmed dry-run only, or
cannot be determined. If any previously reported enforcement turns out to have been dry-run,
that is a correction the dissertation must carry, and it must be flagged clearly rather than
quietly dropped.

## A3. Confirm the capture CSVs are unaffected

The evaluation CSVs in `evaluation/results/` that feed the confusion matrix and the ablation
were captured in earlier rounds, before this session. Confirm their modification timestamps
and git history place them outside both problem windows, so the quantitative results and the
ablation stand unaffected. If any were touched or regenerated this session, identify which.

## A4. Restore normal state

The daemon was left running with `dry_run: false` through a temporary `--config` override.
Restore the normal configuration, confirm only one daemon instance is running, and confirm no
stray miner processes remain. Report the final state.

**Write `reports/INTEGRITY_CHECK.md` with the results of A1 to A4 before starting Part B.**

---

# PART B — Baseline comparison

## Why this is needed

The dissertation argues that resource-threshold monitoring cannot separate cryptomining from
legitimate high-CPU workloads, and that kernel-level behavioural fingerprinting can. That claim
is currently asserted from the literature and never tested. This tests it against data already
on disk. The required Results chapter structure includes a baseline comparison section, and it
is currently the weakest section in the chapter.

## B0. Establish a usable CPU signal (do this first)

The `cpu_percent` column is empty for every pre-detection tick, root-caused in the previous
session to scan-cycle latency. **It is therefore unusable here**, because a baseline detector
must see CPU from t=0 exactly as a real resource monitor would.

Derive CPU utilisation from the scheduler counter `on_cpu_ns`, which `sched_monitor.c`
populates for all processes from the first tick:

```
cpu_fraction over window = delta(on_cpu_ns) / (delta(wall_clock_ns) * n_cores)
```

State the percentage convention used, whether per-core or aggregate. Use a rolling window of at
least 10 seconds to absorb the counter's known coarse update cadence.

**Validate before proceeding.** Check the derived value against a figure already trusted, for
example the 99.7% pre-throttle and 30.0% post-throttle readings in
`evaluation/results/mitigation_effect.md`, or the known-saturating gcc and OpenSSL tracks.
Report the validation. If `on_cpu_ns` is also unusable, say so and stop; the comparison cannot
be made honestly without a CPU signal available from t=0.

## B1. Implement three baseline detectors

Write `evaluation/baseline_detectors.py`. Each consumes the same per-tick observation stream
and emits a binary decision per observation, so results drop into the existing confusion-matrix
machinery unchanged.

- **B1, CPU threshold.** Flag once rolling CPU utilisation stays at or above `T` percent
  continuously for at least `D` seconds. The classic resource monitor the dissertation
  criticises.
- **B2, CPU plus thread saturation.** As B1, additionally requiring
  `thread_count >= cpu_count`.
- **B3, CPU plus compute purity.** As B1, additionally requiring a low I/O ratio derived from
  the `read` and `write` syscall counters already present in the CSVs.

## B2. Sweep the parameters

**Be fair to the baseline.** This comparison is academically indefensible if the baseline is
configured to fail. Sweep `T` across at least {60, 70, 80, 85, 90, 95} percent and `D` across at
least {10, 30, 60, 120} seconds. Compute precision, recall, F1, specificity and false-positive
count for every combination.

Write the full sweep to `evaluation/results/baseline_sweep.csv` and clearly mark the best-F1
configuration for each baseline. Those three configurations are what the comparison uses.

## B3. Comparison table

Reuse the exact methodology of `evaluation/results/confusion_matrix_v2.md`: one process at one
scan tick equals one observation, ground truth by source track, same track set, same labels.
The comparison is void if the denominators differ.

Write `evaluation/results/baseline_comparison.md` reporting all four detectors for **Reading 1**
(all tracks, MEDIUM and above) and **Reading 3** (steady state):

| Detector | Config | n | TP | FN | FP | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|---|

**Then answer the question the whole exercise exists for:** on which specific benign
observations did each baseline fire? Break false positives down by source track, giving counts
and the fraction of each track affected. If the baselines fire on the gcc compilation and
OpenSSL tracks, that is the direct evidence that sustained legitimate compute is
indistinguishable from mining under a resource threshold.

Report the reverse honestly too: any track where a baseline matched or beat EDDMC, and whether
any configuration achieved zero false positives, and if so at what cost to recall.

## B4. Figure

`evaluation/figures/fig_baseline_comparison.png`, 200 dpi, axis labels and legend, no title.

Preferred: precision against recall, plotting each baseline's full sweep as a curve or scatter,
with EDDMC as a single labelled point, showing whether any threshold setting reaches EDDMC's
operating point. Fall back to a grouped bar chart of precision, recall and F1 if that does not
render legibly.

---

## Report back

Two files:

1. `reports/INTEGRITY_CHECK.md` — Part A. Lead with the single most consequential finding.
2. `reports/BASELINE_COMPARISON_NOTES.md` — Part B, covering: whether `on_cpu_ns` yielded a
   usable signal and its validation, the best configuration per baseline with metrics, the
   false-positive breakdown by benign track, anything surprising including results favourable
   to a baseline, and every file produced with paths.