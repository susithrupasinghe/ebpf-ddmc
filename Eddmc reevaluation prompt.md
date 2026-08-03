# Task: Full re-evaluation of EDDMC against the current artifact

## Context

You are in the EDDMC repository. The detection pipeline has changed since the evaluation
reported in `reports/FINAL_EVALUATION.md` and written into Chapter 6 of the dissertation.
XMRig is now expected to reach CRITICAL tier, whereas the previously reported evaluation
recorded a peak of 45 to 46 at MEDIUM tier for the same workload.

That single change invalidates most of Chapter 6, because the reported results are tied to the
old scoring behaviour. This task re-runs the evaluation end to end against the current code so
the chapter can be rewritten from current evidence.

## What the previous evaluation reported

These are the figures currently in the dissertation. They are listed so you can report what
has changed rather than only what the new numbers are.

| Measure | Previously reported |
|---|---|
| XMRig peak score | 45.0 to 46.0, MEDIUM tier |
| Weighted sum at peak, excluding floors | 38 for ground truth, 20 for self-throttled evasion |
| Time to MEDIUM tier | 104.0s pre-fix, 22.2s post-fix |
| Precision, all readings | 1.000 |
| Recall, Reading 1 all tracks | 0.626 |
| Recall, Reading 3 steady state | 0.891 |
| F1, Reading 3 | 0.942 |
| False positives | 0 across 5,097 benign observations |
| Mitigation effect | 99.7% to 30.0% utilisation |
| Daemon overhead at idle | 66.2% of one core after optimisation |
| Registry time to detection | 39.1s matched against 89.7s unmatched |
| Matcher false positives | 0 across 34,979 benign observations |
| Scan cycle gaps | mean 20.2s pre-fix, approximately 10s post-fix |

## Ground rules

- **Never invent a value.** Every figure must trace to a CSV row, a log line, or code you can
  cite. If something cannot be measured, report it as not measured.
- **Do not overwrite the existing results.** Write everything new to
  `evaluation/results/final_v2/`. The old data must remain intact until the new set is verified,
  because the dissertation currently depends on it.
- **Commit with a clean working tree before each capture** and record the git SHA in the output.
  A previous round recorded `dirty=True`, which is not reproducible for a dissertation.
- **Confirm exactly one daemon instance** before every capture, and confirm `mitigation.dry_run`
  is false where enforcement is being measured. Both have silently corrupted results in this
  project before: a systemd-managed daemon once ran in parallel with a manually started one, and
  `daemon/config/local.yaml` defaults `dry_run` to true.
- **No external network.** Mining runs use a local mock stratum listener only. No pool, no
  wallet, no public endpoint.
- **Do not tune thresholds to produce a result.** If a threshold changes, every affected
  measurement must be re-run and the change documented as a design decision with its rationale.

---

## Task 0 — Record what changed

Before running anything, produce `reports/ARTIFACT_DELTA.md` stating what has changed in the
detection pipeline since the previous evaluation. Specifically:

- Which features, weights, hard-evidence floors, or tier boundaries were altered, with before
  and after values.
- Whether the change is a correction of a defect, a recalibration, or new functionality.
- Which of the previously reported findings are expected to change as a result.

This matters because Chapter 6's central analytical finding is that the weighted model produced
sums of 38 and 20 against a hard-evidence floor of 45, so detection was carried by a single
conjunctive signal rather than by the breadth of the weighted model. If the floors or weights
have changed, that finding may no longer hold and the chapter's argument changes with it.

---

## Task 1 — Re-capture every track

Re-capture all workloads under the current artifact, using the same capture instrument and the
same one to two second polling interval as before, so the new data is directly comparable in
form to the old.

**Mining tracks:**

1. XMRig, full speed, against the local mock stratum listener
2. XMRig, renamed executable
3. XMRig, single thread, the self-throttled evasion case
4. XMRig, UPX packed
5. XMRig, work split across four single-threaded processes
6. Stratum port client, three trials, captured over at least 90 seconds so process lifetime
   exceeds the scan cadence
7. Browser WASM miner

**Benign tracks:**

8. OpenSSL speed, three trials, at least five minutes each
9. GCC parallel compilation, three trials, at least five minutes each

Each capture must retain per-observation granularity with raw feature values as well as the
composite score, since the confusion matrix and the ablation both depend on it.

For each track report peak score, tier reached, time to first LOW-tier alert, time to MEDIUM,
time to HIGH, time to CRITICAL, and the mitigation applied.

---

## Task 2 — Classification performance

Recompute the confusion matrix using the identical methodology as
`evaluation/results/confusion_matrix_v2.md`: one process at one scan tick is one observation,
detector-positive at MEDIUM tier or above, ground truth assigned by source track.

Report all four readings with n stated for each:

1. All positive tracks, MEDIUM tier and above
2. Mining tracks only, excluding the stratum port and browser WASM tracks
3. Steady state, excluding each track's pre-detection window under a uniformly applied rule
4. Any alert tier, LOW and above

For each, report precision, recall, F1, specificity and false-positive rate. Apply the rule of
three to the negative class and report the 95% upper confidence bound on the false-positive rate.

**Report the negative class composition**, since previously a single workload contributed 4,906
of 5,097 negative observations and that qualification belongs in the write-up.

---

## Task 3 — Ablation and sensitivity

Replay the current scorer against the new captures using `evaluation/replay_scorer.py`, first
verifying that the replay reproduces the daemon's own recorded peak score for every track before
any ablation is trusted.

Produce both readings, as before:

- **Weight-only ablation**: zero each feature's weight in turn, leaving raw evidence intact
- **Evidence ablation**: additionally zero the underlying raw evidence, which disables any
  hard-evidence floor it would trigger

For each mining track, report the weighted sum at the peak observation **separately from the
final score**, so it is visible whether a floor is still determining the outcome or whether the
weighted model now reaches the tier on its own. This is the single most important number for the
chapter's analytical argument.

Also produce the per-feature contribution breakdown at each track's peak observation, and state
explicitly which features now contribute non-zero that previously contributed zero.

---

## Task 4 — Mitigation cascade

Run at least three trials against a live miner with real enforcement enabled, and report per
trial:

- Peak score and tier
- Whether HIGH tier was reached and whether the outbound network block appeared in the active
  firewall rules, verified by reading kernel state rather than the daemon log
- Whether CRITICAL was reached and sustained, and whether suspension was actually delivered
- **Reversibility**: drive the score back below each boundary while the process is alive and
  confirm the cgroup quota and firewall rules are removed and the process resumes
- Time from tier crossing to enforcement applied

Also measure the effect of throttling by sampling processor utilisation independently of the
daemon, at a one-second external poll, reporting mean utilisation before and after enforcement.

Do not enable automatic termination.

---

## Task 5 — Detection latency

Report time to first alert per track against the configured five-second scan interval, with mean
and standard deviation where multiple trials exist.

Measure real scan cycle gaps at debug logging level and report the distribution, the mean, and
the inflation factor against the configured interval. Report the tracked-process count per cycle
alongside, since the two are related.

---

## Task 6 — Runtime overhead

Four conditions on a quiet host, minimum three trials each, at least 300 seconds per trial:

1. Daemon stopped, system baseline
2. Daemon running, no target workload
3. Daemon running, benign high-CPU workload
4. Daemon running, miner active

Verify the host is quiet before starting by reporting 60 seconds of system-wide baseline with the
daemon stopped. If the peak exceeds roughly 20% of one core, stop and report the host as
unsuitable rather than producing an untrustworthy figure.

Report daemon CPU and resident memory separately from system-wide figures, state the
normalisation convention explicitly, and report the marginal overhead as condition 2 minus
condition 1. Include a per-thread profile so the cost is attributable.

---

## Task 7 — Fingerprint registry

Check all five confirmation gate conditions against the new peak observations and report which
pass. If the gate is now reachable without recalibration, say so, since the previous round
required one condition to be replaced.

Then run the two-node experiment: Node A to confirmation with a fingerprint reaching the
registry, Node B with no detection history running the same variant, measuring time from process
start to first HIGH-tier alert with matching enabled and disabled, three trials per condition,
mean and standard deviation.

Run the matcher against every benign observation and report actual cosine similarity scores
against the operating threshold, not pass or fail.

If a second host is unavailable, simulate Node B by clearing the process store and fingerprint
cache, and state plainly that this is a same-host simulation.

---

## Task 8 — Baseline comparison

Implement three baseline detectors and evaluate them against the identical observation set and
decision convention used in Task 2: a sustained CPU threshold, that threshold combined with
thread saturation, and that threshold combined with a low input and output ratio.

**Be fair to the baselines.** Sweep the utilisation threshold across at least {60, 70, 80, 85,
90, 95} percent and the sustained duration across at least {10, 30, 60, 120} seconds, and report
each baseline at its best configuration by F1. A comparison against a deliberately weak baseline
is indefensible.

Derive processor utilisation from a signal available from process start. Validate it against a
known figure before use, and report the validation.

Break false positives down by source track with counts and the fraction of each track affected.
Report honestly any configuration where a baseline matches or beats the artifact.

---

## Report back

Write `reports/FINAL_EVALUATION_V2.md` containing every table above, and open it with a
comparison against the previously reported figures listed at the top of this document, in the
form:

| Measure | Previous | Current | Changed? |

Then state directly, in the first two paragraphs:

1. **What peak score and tier XMRig now reaches**, and whether the weighted model alone reaches
   that tier or whether a hard-evidence floor is still determining the outcome.
2. **Whether precision remains 1.000 with zero false positives**, since that is the strongest
   result in the dissertation and the one most exposed by a scoring change that raises scores.

Finish with a per-task statement of completed, partially completed, or not attempted, and why.

---

## A note on scope

This is a full re-evaluation, not a spot check. If time is limited, the priority order is Task 1,
Task 2, Task 3, Task 4, then the rest. Tasks 1 to 4 are sufficient to rewrite the core of the
chapter; Tasks 5 to 8 refine it. Report partial completion honestly rather than rushing a task to
the point where its numbers cannot be defended.