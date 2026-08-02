# Task: Close RO2, RO6 and RO7 — with explicit pass criteria

## Context

You are in the EDDMC repository, continuing from `reports/FINAL_EVALUATION.md`. That round
closed RO4 properly: all three cascade trials reached CRITICAL with cgroup, iptables and SIGSTOP
enforcement verified in kernel state, and reversibility confirmed. That work stands and does not
need repeating.

That report also marked RO2, RO6 and RO7 as met. On review, the underlying data does not support
those three. This task establishes what is actually needed to close them.

## The central rule for this round

**Measuring something is not the same as meeting it.** RO2 asks for a *lightweight* daemon. The
last round measured 163.6% of one core at idle, which on a four-core host is 41% of the machine
consumed by a monitoring daemon doing nothing. That measurement is credible, since the system
baseline was a genuinely quiet 7.0%. It answers RQ4, and the answer is that the daemon is not
lightweight. RO2 therefore cannot be marked met on that evidence.

Each objective below has a **numeric pass criterion stated in advance**. Apply it literally. If a
criterion is not reached, mark the objective partially met, state the figure achieved, and move
on. Do not restate a criterion to match the result obtained.

## Ground rules

- Never invent a value. Every figure traces to a CSV row, a log line, or code you can cite.
- Continue using the single `evaluation/eddmc_eval.py` entry point. No new standalone scripts, no
  additional markdown reports. One report out at the end.
- Commit before each measurement run, record the git SHA, and **commit with a clean working tree**
  — the last `platform.json` recorded `dirty=True`, which is not reproducible for a dissertation.
- Confirm exactly one daemon instance and that `dry_run` is false before any capture.
- Mining runs use the local mock stratum listener only. No external pool or wallet.

---

# TASK 1 — RO2: make the daemon lightweight, then re-measure

**Pass criterion: marginal daemon CPU overhead at idle below 25% of one core, and RSS below
150 MB, both as a mean across at least 3 trials.** Current figures are 163.6% and 232.8 MB.

This task requires optimisation, not just measurement. Measuring again without changing anything
will produce the same number.

## 1.1 Confirm the cause before changing anything

The working hypothesis is that the eBPF collectors are cheap and the expense is the single-threaded
Python scoring loop iterating the full tracked-process population, measured at 889 to 1,912 entries
per cycle. Profile the running daemon and report the actual split between collector threads and the
scoring loop. If the hypothesis is wrong, report that and the optimisation below will need
rethinking.

## 1.2 Implement a scoring pre-filter

Admit a process to full scoring only when it exceeds a coarse activity threshold, for example a
minimum CPU utilisation or syscall rate over the preceding window. Everything below the threshold is
tracked but not scored.

Constraints that make this safe:

- The threshold must sit **well below** any level at which a miner could operate. A miner that
  throttled itself beneath the filter would evade detection entirely, which would trade an overhead
  problem for a much worse detection problem. Justify the chosen value against the observed CPU
  utilisation of the self-throttled evasion track, which is the lowest-activity mining workload on
  record.
- Do not change scoring weights, thresholds, floors or tier boundaries. Only which processes are
  scored.
- Consider filtering inside the eBPF programs as well, if the profile shows collector-side cost.

## 1.3 Re-measure overhead

Repeat all four conditions from the previous round: daemon stopped, daemon idle, daemon with a
benign workload, daemon with XMRig. Minimum 3 trials each, at least 60 seconds per trial, on the
same quiet host so the figures are directly comparable to the 163.6% baseline.

Report the before and after side by side, and the tracked-process count and scored-process count
per cycle in both configurations.

## 1.4 Verify detection is unaffected — this is mandatory

An optimisation that reduces overhead by weakening detection is worse than no optimisation. Re-run
and confirm all three of the following against the filtered daemon:

- **The cascade run.** Must still reach CRITICAL with all enforcement verified in kernel state.
  If this regresses, RO4 breaks, and RO4 currently holds.
- **The self-throttled evasion track.** Must still be detected. This is the workload most likely to
  fall beneath an activity filter.
- **The benign tracks.** Must still produce zero false positives.

**If any of these three regresses, revert the filter and report RO2 as partially met.** Detection
integrity is not negotiable against an overhead figure.

---

# TASK 2 — RO7: run the two-node experiment

**Pass criterion: time-to-detection measured with and without fingerprint matching, minimum 3
trials per condition, mean and SD reported for both.**

The previous round skipped this by misapplying a stop condition. Gate recalibration attempt 1 was
rejected when 30 of 5,097 benign observations passed. Attempt 2 was **accepted** with 0 of 5,097
passing, and also passes on the real cascade peak. The gate is therefore reachable and
poisoning-tested, and the two-node experiment should have proceeded.

## 2.1 Node A

Run the cascade workload to confirmation and verify a fingerprint actually reaches the registry
server. Report the fingerprint contents and confirm the server stored it.

**Check one thing while you are here.** A prior artefact inventory found that
`daemon/fingerprint/packager.py` submits the value of `thread_cpu_ratio` under the string key
`thread_density`. If that mislabelling is still present, any cross-node comparison is
comparing mismatched fields. Fix it before running Node B, and report that you did.

## 2.2 Node B

An independent instance with no detection history. If a second host is available, use it. If not,
simulate by stopping the daemon, clearing the process store and fingerprint cache entirely, and
restarting — and state plainly in the report that this is a same-host simulation rather than a true
cross-host test. A disclosed simulation is acceptable evidence; an undisclosed one is not.

Run the same miner variant and measure **time from process start to first HIGH-tier alert**, under
two conditions:

- Fingerprint matching enabled, with Node A's fingerprint present in the registry
- Fingerprint matching disabled, or registry empty

Minimum 3 trials per condition. Report mean and SD for each, and the difference between them. That
difference is the detection-acceleration benefit, which is the actual content of RO7.

## 2.3 Matcher false positives

Run the matcher against every benign workload and report actual cosine similarity scores, not pass
or fail. Confirm no benign process is elevated by matching.

---

# TASK 3 — RO6: a valid baseline comparison

**Pass criterion: all seven tracks recaptured under the fixed collector, all three baselines
producing finite metrics, and a non-empty per-track false-positive breakdown.**

The previous baseline result must not be used. It reported a naive 80% CPU threshold achieving
precision 1.000, recall 1.000 and F1 1.000, which would mean a trivial resource check outperforms
the entire system. It is not a real result, for three reasons: only 4 of 7 tracks were included;
`fp_by_track` was empty in every case, meaning the benign set never challenged the baseline at all;
and B3 returned `nan` with recall 0.000, which is a broken implementation rather than a finding.

## 3.1 Recapture the full track set

Recapture all seven tracks under the fixed collector so the baseline and EDDMC are evaluated on
identical data: XMRig ground truth, self-throttled evasion, UPX-packed, three network pool-hits
trials, browser WASM miner, plus the benign OpenSSL and GCC tracks.

If a track genuinely cannot be recaptured, exclude it from **both** the baseline and the EDDMC side
of the comparison and say so. Never compare a baseline on four tracks against EDDMC figures computed
on seven.

## 3.2 Fix B3

B3 returning `nan` with zero recall means the I/O ratio condition never evaluates true. Debug it.
Report the actual cause. If the read and write syscall counters are unpopulated, say so and drop B3
rather than reporting a broken detector as though it were a weak one.

## 3.3 Run the comparison properly

Sweep `T` across {60, 70, 80, 85, 90, 95} and `D` across {10, 30, 60, 120}. Report each baseline's
best configuration by F1 for Reading 1 and Reading 3, alongside EDDMC on the same data.

**Then break false positives down by source track, with counts and the fraction of each track
affected.** An empty breakdown means the benign observations are not entering the sweep; that is a
bug, not a result showing zero false positives.

**Report the outcome honestly whichever way it falls.** If a baseline genuinely matches or beats
EDDMC on the full dataset, that is a real and important finding and it must be reported as such.
The value of this comparison lies in it being trustworthy, not in it being favourable.

---

# TASK 4 — Report

Update `reports/FINAL_EVALUATION.md`. Open with a status table applying the criteria above
literally:

| RO | Criterion | Achieved | Met? |
|---|---|---|---|
| RO2 | Marginal CPU below 25% of one core, RSS below 150 MB | | |
| RO4 | CRITICAL reached, enforcement in kernel state, reversibility | Yes, prior round | Met |
| RO6 | 7 tracks, 3 baselines finite, per-track FP breakdown | | |
| RO7 | Time-to-detection both conditions, 3 trials, mean and SD | | |

For any objective not met, state the figure achieved and precisely what remains. **Do not mark an
objective met unless its stated criterion is satisfied.**

Also carry forward two items for the dissertation's limitations section, both found in the previous
round and both worth keeping:

- After revoke lifts enforcement, the daemon's status column continues to display CRITICAL, because
  the score does not fall and tier escalation only re-fires on a strict increase. Enforcement
  reversal is real; the status display does not reflect it.
- A stale observation defect was found during gate work: a process with only 177 syscalls across a
  30-second capture was polled repeatedly and counted as 30 separate confirmations.

---

## Priority and stopping

Task 2 is most likely to close, since the gate is already reachable and poisoning-tested and only
the measurement remains. Task 3 is next, being mostly recapture time. Task 1 is the hardest, because
it requires a real optimisation and carries a risk of regressing detection.

Stop and report rather than expanding scope. Three objectives met with honest accounting is a
stronger position than four claimed on evidence that does not hold, and the dissertation already
reports partially met objectives with full explanations.