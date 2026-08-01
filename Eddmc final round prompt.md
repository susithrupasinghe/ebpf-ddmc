# Task: Close the four partially met research objectives, using one consolidated script

## Context

You are in the EDDMC repository. The dissertation's Results chapter is written and reports
three of seven research objectives as fully met and four as partially met. In every one of the
four, the component was designed and built; what is missing is its **evaluation**. This task
closes those evaluation gaps.

| RO | Objective | What is missing |
|---|---|---|
| RO2 | Lightweight eBPF daemon | Runtime overhead never measured; the "lightweight" claim is unverified |
| RO4 | Policy-driven mitigation | Only the throttle tier was ever exercised; block, suspend and terminate never fired |
| RO6 | Evaluate across five dimensions | Overhead missing, and no controlled baseline comparison exists |
| RO7 | Fingerprint registry | Built and deployed, but the confirmation gate was never reachable, so nothing was evaluated |

Two recent changes make these achievable. The scheduler TID-attribution defect is fixed, which
unblocks the baseline comparison that was previously abandoned at its validation gate. And the
post-fix verification showed a live XMRig peak of 52 from weighted signals alone, meaning the
addition of a pool connection signal could plausibly carry the score into HIGH and CRITICAL tiers
for the first time.

## Two hard requirements

**1. Consolidate into one script.** The evaluation directory has accumulated many single-purpose
scripts and reports. Everything in this task must be driven by **one** file,
`evaluation/eddmc_eval.py`, exposing subcommands. Move the existing one-off scripts into
`evaluation/archive/` rather than deleting them, since prior results must remain reproducible.
Do not create new standalone scripts, and do not write a separate markdown report per task.

**2. Never invent a value.** Every figure traces to a CSV row, a log line, or code you can cite.
If something cannot be established, report it as not established. An objective that stays
partially met with an honest explanation is a better outcome than one made to look met.

## Ground rules

- Commit before each measurement run and record the git SHA in the output.
- Every run writes `platform.json` capturing kernel, architecture, core count and memory.
- Confirm exactly one daemon instance before any capture. A duplicate systemd instance and a
  dry-run default have both silently corrupted results in this project before. Check both.
- Mining runs use a **local mock stratum listener only**. No external pool, wallet or endpoint.
- Do not tune a threshold to make a test pass and then report that test as independent
  validation. Where recalibration is warranted, it must be argued from observed data and every
  affected result re-run.

---

## The consolidated script

`evaluation/eddmc_eval.py`, one entry point, subcommands below. Shared helpers live in the same
file: daemon lifecycle, capture loop, CSV writing, metric computation.

```
python3 evaluation/eddmc_eval.py overhead    [--trials 5] [--duration 300]
python3 evaluation/eddmc_eval.py capture     --track NAME [--duration 300] [--pool]
python3 evaluation/eddmc_eval.py cascade     [--duration 300]
python3 evaluation/eddmc_eval.py baseline    [--replay-dir evaluation/results]
python3 evaluation/eddmc_eval.py registry    [--mode gate-replay|two-node]
python3 evaluation/eddmc_eval.py report
```

**Output discipline.** All raw data goes to `evaluation/results/final/` as CSV or JSON, one file
per run, named `{subcommand}_{track}_{timestamp}.csv`. The `report` subcommand reads everything
in that directory and emits **one** markdown file, `reports/FINAL_EVALUATION.md`, containing every
table the dissertation needs. No other markdown is produced by any subcommand.

---

## RO4 and RO7 — Task A: mock stratum listener and full cascade

This is first because it has the most leverage: it is the only route to exercising the upper
mitigation tiers, and the only route to making the registry gate reachable.

### A1. Mock stratum listener

Implement inside `eddmc_eval.py`, not as a separate file. A local TCP listener on port 3333 that
accepts connections and holds them open. If XMRig disconnects on invalid job data, implement a
minimal stratum handshake sufficient to keep the socket alive; report which was needed.

### A2. Cascade capture

`eddmc_eval.py cascade` runs XMRig against `127.0.0.1:3333`, full threads, **not** `--bench`, with
`dry_run: false`, for at least 300 seconds. Capture every scan tick with score, tier, mitigation
state, and each feature's raw value and weighted contribution.

Report, per trial, minimum three trials:

- Peak score and tier reached.
- Whether HIGH (60+) was reached, and if so whether the **network block actually appeared in
  iptables or nftables rules**. Verify in the kernel's own state, not from the daemon log.
- Whether CRITICAL (80+) was reached and sustained, and whether SIGSTOP was actually delivered.
  Do not enable automatic termination; verify suspension only, and confirm the process resumes
  when the score falls back.
- **Reversibility**: drive the score back below each boundary while the process is still alive and
  confirm the cgroup quota and firewall rules are removed. This is required for RO4 and has never
  been tested.
- The full feature contribution breakdown at peak.

### A3. Registry confirmation gate

Check all five gate conditions against the peak observation from A2 and report which pass.

The three feature thresholds are `futex_ratio >= 0.40`, `cpu_bound_ratio >= 0.92`, and
`thread_cpu_ratio >= 1.0`. Chapter 6 established that futex ratio measures approximately 3.1% for
RandomX, because RandomX workers hash rather than synchronise, so that condition cannot pass for
the workload the system is designed to detect. This is a calibration error carried over from the
design phase, not a property of the workload.

**If the gate does not pass, recalibrate it — but only on this basis:**

- Derive each replacement threshold from the **observed distributions** across the existing mining
  and benign captures, not from what makes the test pass. Report the distributions you used.
- The recalibrated gate must be **at least as strict against benign data** as the original.
  Prove this in A4 before using it for anything.
- Document the original gate, the recalibrated gate, and the empirical justification for each
  change, in a form the dissertation can cite as a design refinement.

### A4. Poisoning resistance (required before any recalibration is accepted)

Replay both the original and recalibrated gates offline against **every** benign capture in
`evaluation/results/`, including all 5,097 benign observations behind the existing confusion
matrix. Report how many benign observations pass each gate.

If any benign observation passes the recalibrated gate, the recalibration is rejected. Report that
and stop; do not proceed to A5. If zero pass, this is the poisoning-resistance evidence the
methodology chapter promised and has never had.

### A5. Two-node experiment

Only if A3 or A4 leaves the gate reachable and safe.

- Node A: run to confirmation, verify a fingerprint reaches the registry server.
- Node B: independent instance, no detection history, same miner variant.
- Primary metric: time from process start to first HIGH-tier alert, **with** and **without**
  fingerprint matching enabled. Minimum three trials per condition, report mean and SD.
- Secondary: run the matcher against every benign workload and report actual cosine similarity
  scores, not pass or fail.

If a second host is unavailable, simulate Node B by clearing the daemon's process store and
fingerprint cache entirely, and say plainly in the report that this is a same-host simulation
rather than a true cross-host test.

---

## RO2 and RO6 — Task B: runtime overhead

`eddmc_eval.py overhead`. Previously abandoned because the shared development host showed ambient
CPU excursions above 230% of one core with the daemon stopped.

**The host matters more than the tooling here.** In order of preference: a fresh low-cost VPS for
24 hours, ideally x86-64 so it also closes the architecture mismatch; or the existing machine
rebooted with every application, IDE and browser closed and left otherwise idle. Verify the host is
quiet before proceeding: sample 60 seconds of system-wide CPU with the daemon stopped and report
mean and peak. **If the peak exceeds roughly 20% of one core, stop and report the host as
unsuitable** rather than producing another unusable figure.

Four conditions, five trials each, at least 300 seconds per trial:

1. Daemon stopped, system baseline
2. Daemon running, no target workload
3. Daemon running, benign high-CPU workload
4. Daemon running, XMRig active

Report daemon CPU and RSS separately from system-wide figures, state explicitly whether CPU is
per-core or aggregate across N cores, and report the **marginal overhead** as condition 2 minus
condition 1. That difference is the number RO2 actually needs.

Also report the tracked-process count on the clean host. Earlier rounds saw 889 to 1,912 entries.
If it is far lower here, then both the overhead figure and the scan-latency inflation may be partly
artefacts of the previous test machine, which would change what the dissertation says about the
GIL limitation.

---

## RO6 — Task C: baseline comparison

`eddmc_eval.py baseline`. Previously blocked because `on_cpu_ns` was keyed by thread ID; that is
now fixed, so this should work.

**Validate the CPU signal first.** Derive utilisation from `on_cpu_ns` and check it against a known
value, for example the 99.7% pre-throttle and 30.0% post-throttle readings already on record.
Report the validation. If it still fails, stop and report.

Implement three baselines, all inside `eddmc_eval.py`:

- **B1** CPU threshold: flag once rolling utilisation stays at or above `T`% for `D` seconds.
- **B2** B1 plus `thread_count >= cpu_count`.
- **B3** B1 plus a low I/O ratio from the read and write syscall counters.

**Be fair to the baselines.** Sweep `T` across {60, 70, 80, 85, 90, 95} and `D` across {10, 30, 60,
120}, and report each baseline's **best** configuration. A comparison against a deliberately weak
baseline is worthless and an examiner will say so.

Evaluate against the identical observation set, ground truth assignment and decision convention as
`confusion_matrix_v2.md`, for Reading 1 and Reading 3. Then answer the question the exercise exists
for: **on which specific benign observations did each baseline fire?** Break false positives down
by source track with counts and the fraction of each track affected. Report honestly any track
where a baseline matched or beat EDDMC, and whether any configuration reached zero false positives
and at what cost to recall.

---

## Task D: consolidated report

`eddmc_eval.py report` reads `evaluation/results/final/` and emits `reports/FINAL_EVALUATION.md`
containing, in this order:

1. Platform and artefact version for every run
2. **Objective status table**: each of RO2, RO4, RO6, RO7 marked met or still partially met, with
   the specific evidence and, where still partial, exactly what remains
3. Cascade results: tiers reached, enforcement verified in kernel state, reversibility
4. Gate: original conditions, recalibrated conditions with justification, poisoning replay result
5. Two-node time-to-detection, or a statement that it was not performed
6. Overhead: four conditions with mean and SD, marginal overhead, tracked-process count
7. Baseline comparison table and the false-positive breakdown by track
8. Anything that failed, was inconclusive, or was not attempted, and why

Also emit `evaluation/figures/fig_cascade_progression.png` showing score against time for the
cascade run with all four tier boundaries and the point at which each enforcement action fired.
This is the figure that visually demonstrates RO4.

---

## Priority if time runs short

Task A is worth the most: it closes RO4 and potentially RO7, which are two of the four gaps, and it
is the only irreplaceable piece since nothing else can substitute for exercising the upper cascade.
Task B closes RO2 and half of RO6, and needs a quiet host more than it needs effort. Task C closes
the other half of RO6.

Stop and report at any point rather than expanding scope or producing a figure the data does not
support. A partially met objective, honestly explained, is already written into the dissertation and
costs nothing to leave as it stands.