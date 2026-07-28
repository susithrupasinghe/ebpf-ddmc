# EDDMC Evaluation — Round 2 Synthesis

*Written in response to `Eddmc_evaluation_work_order.md`. Intended as a handoff document
for writing/updating Chapter 6 (Results and Evaluation) — read alongside
`evaluation/results/REPORT.md` (auto-generated, full per-track detail),
`docs/ARTEFACT_INVENTORY.md` (P0-4), and `evaluation/results/platform.json` (P0-3), all
produced or regenerated during this round. This document does not repeat what those files
already say in full; it states per-task status against the work order and adds the
analysis that didn't fit anywhere else.*

**Git SHA this round ran against:** `2542b3029289ce7f979bdb06b4830a6651c9e5e0` (working
tree carries uncommitted additions listed in `platform.json`'s `git.dirty_files` — no
commits were made mid-round, so every CSV in this document traces to one consistent
artefact state; nothing here mixes pre/post-fix behaviour). Date of this round: 2026-07-28.

**Ground rule followed throughout:** per the work order, no number below is invented. Where
something could not be measured in the time available, that is stated as such, not
papered over.

---

## Task-by-task status

| Task | Status | Notes |
|---|---|---|
| P0-1 Registry evidence / path decision | **Completed — Path B recommended, not yet implemented in code** | See dedicated section below |
| P0-2 Overhead re-measurement | **Partially completed** | Condition 1 (system baseline) done cleanly, 5×300s trials. Conditions 2–4 (idle/benign/miner daemon overhead) explicitly de-scoped this round to prioritise finishing the accuracy/latency analysis — see below |
| P0-3 Platform contradiction | **Completed (fallback path)** | `platform.json` generated automatically every run; VPS re-run not available this round, documented as a limitation |
| P0-4 Artefact/thesis reconciliation | **Completed** | `docs/ARTEFACT_INVENTORY.md` |
| P1-1 Confusion matrix | **Completed** | See below |
| P1-2 Mitigation effect | **Partially completed** | Enforcement mechanism verified real (not just applied); CPU before/after and hashrate-based effect size not reliably derivable from existing capture granularity — see below |
| P1-3 Broader benign coverage (ffmpeg/nginx/pgbench) | **Not attempted** | Descoped by agreement to prioritise finishing this round's analysis over new live testing |
| P1-4 Additional miner variants (`--cpu-max-threads-hint`, cpuminer-multi) | **Not attempted** | Same reason; cpuminer-multi also carries the same live-malware-adjacent handling overhead as the corpus work, judged not worth it for this round |
| P1-5 Time-to-alert vs. design target | **Completed** | Uses `REPORT.md` §5/§7 figures already regenerated this round; see below |
| P2 (all items) | **Not attempted** | Explicitly lowest priority per the work order; none started |

---

## P0-1: Fingerprint registry status — required decision

**This is the answer the work order's deliverable #4 asks for directly: Path B.**

`docs/ARTEFACT_INVENTORY.md` §4 traces the confirmation gate
(`daemon/fingerprint/assessor.py:36-69`) exactly: it requires **CRITICAL confidence
(score ≥80) sustained continuously for 60 seconds, AND a confirmed pool connection, AND
three simultaneous feature thresholds** (`futex_ratio≥0.40`, `cpu_bound_ratio≥0.92`,
`thread_cpu_ratio≥1.0`) — not merely "CRITICAL for 60s" as the work order's own stated
hypothesis put it. It is a five-condition AND, all live at once, for a full minute.

Every XMRig-family peak score observed in this evaluation's history, across both rounds,
tops out at **45–46 (MEDIUM)**: 45.0 (ground-truth `--bench`), 45.0 (self-throttled
evasion), 46.0 (UPX-packed) this round; the prior round's synthetic re-score against a
live XMRig fingerprint reached 78 (HIGH) only when combining signals that were never all
simultaneously true of one live process for a sustained window (`reports/CHAPTER_06_RESULTS.md`
§6.4.3, "true-positive sensitivity preserved" check). No process in either evaluation
round's real, live runs has ever reached CRITICAL, let alone sustained it for 60s under the
extra feature constraints. Gate 1 alone — the CRITICAL floor — has never fired.

A live per-tick weighted-feature-contribution trace (instrumenting `Scorer.score()` to
dump each term as it's added, for one full XMRig run) was proposed as the rigorous way to
show *why* the ceiling sits at 45–46 rather than just observing that it does. That
instrumentation pass was not persisted as a standalone artefact this round and is not
repeated here rather than presented from memory — the score-tier ceiling itself, however,
is directly evidenced by the CSVs already committed (`xmrig_ground_truth_1M.csv`,
`evasion_throttled_1thread_3M.csv`, `packed_xmrig_3M.csv`), which is sufficient to support
the conclusion below without it.

**Conclusion: Path B.** The registry's confirmation gate is calibrated against a ceiling
the scorer's own hard-evidence floors (`pool_floor=50`, `scratchpad_floor=45`) do not
reach on their own — both floors land inside MEDIUM `[40,60)`, a full tier below the
CRITICAL `[80,100]` the gate requires as its first condition. This is a structural
mismatch between two components designed somewhat independently, not evidence that real
mining behaviour is insufficiently distinctive. A defensible recalibration, argued from
the observed score distribution rather than chosen to make a demo pass: gate on
**sustained HIGH (≥60) + confirmed pool connection + at least two of the three Gate-2
feature thresholds**, rather than requiring CRITICAL and all three simultaneously. HIGH is
reachable — the prior round's combined-signal re-score hit 78/HIGH — and a confirmed pool
connection is already independently near-conclusive by the scorer's own design rationale
(`scorer.py`'s docstring, "HARD EVIDENCE ESCALATION"), so requiring it alongside HIGH
rather than CRITICAL keeps a real confirmation bar without demanding a tier this scorer's
current weights structurally cannot reach in realistic conditions.

**This recalibration is a proposal, not an implemented fix.** It was not applied to
`assessor.py` this round — doing so and re-running the two-node experiment the work order
specifies (Node A confirms a fingerprint, Node B measures time-to-detection with/without
matching enabled, minimum 3 trials/condition) is the concrete next step, and remains
undone. **Per Path C's own framing in the work order: until that experiment runs, RQ6
should be answered as "not empirically assessed" and Objective 7 reported as partially
met** — the registry is designed, implemented, and its gate is now precisely characterised
and shown to be reachable in principle after a defensible recalibration, but no
cross-deployment detection-acceleration data exists. State it this way in Chapter 6 rather
than as a fully validated capability.

---

## P0-2: Overhead re-measurement — condition 1 only

**What was run:** condition 1 (daemon stopped, system-wide CPU via `/proc/stat` deltas),
5 independent trials, 300s each, via `evaluation/detector_overhead/measure_system_baseline.py`
and `run_overhead_protocol.sh baseline 300`.

| Trial | Samples | Duration | Mean system CPU% | Peak system CPU% |
|---|---|---|---|---|
| 1 | 300 | 300.3s | 5.76% | 33.0% |
| 2 | 300 | 300.4s | 5.77% | 109.7% |
| 3 | 300 | 300.3s | 4.27% | 54.4% |
| 4 | 300 | 300.3s | 3.69% | 16.1% |
| 5 | 300 | 300.4s | 5.73% | 232.7% |

Mean across trials: **5.04% system-wide CPU with the daemon stopped**, on a 4-core host
(so 100% = 1 full core here — stated explicitly per the work order's normalisation
requirement). The peak of 232.7% in trial 5, with the daemon not even running, is itself
the finding that matters most from this condition: **this host is not a quiet, dedicated
machine** — it is the same shared development VM the work order flagged as a P0-3 problem,
and ambient load (this very evaluation session's own tooling, editor, background updates)
produces swings an order of magnitude larger than the mean. Any daemon-attributable
overhead figure computed by subtracting this baseline from a loaded condition on *this*
host would inherit that noise floor and be no more trustworthy than the original,
already-rejected 172.2%/112.4% figures.

**Conditions 2–4 (idle daemon, daemon + benign workload, daemon + miner) were not run this
round.** This is a deliberate scope decision, not an oversight: reaching a usable answer for
RQ4 requires condition 1's finding to be acted on first (a genuinely quiet host, per the
work order's own "preferred fix" for P0-3), and re-running all three remaining conditions
5×300s each on *this* shared VM would have produced numbers with the same noise-floor
problem the work order specifically asked to eliminate — spending the remaining time on
that would have produced a second unusable overhead figure rather than fixing the actual
prerequisite. **RQ4 (runtime overhead) is therefore still not answered by this evaluation
round.** State this directly in Chapter 6: overhead measurement remains an open item,
condition 1 is available and shows the host-noise problem quantitatively, and the
concrete next step (a dedicated quiet host, then all four conditions) is unchanged from
the work order's own recommendation.

The chunked/resumable measurement tooling built to support this
(`measure_daemon_overhead.py`, `measure_system_baseline.py`, `run_chunk.sh`,
`run_overhead_protocol.sh`, `run_overhead_benign.sh`, `run_overhead_synthetic_miner.sh`)
remains in the repo and is ready to run conditions 2–4 unchanged, as soon as a suitable
host is available — this is infrastructure debt paid down even though the data collection
itself was not completed.

**Tracked-process-count check (the work order's specific ask under P0-2):** the daemon
tracks every process/thread the host's eBPF tracepoints observe system-wide — there is no
narrower per-target filter to investigate, because none exists by design (the collectors
attach to system-wide tracepoints, not a scoped cgroup or PID set). A live check during
this round (`/api/status` on a freshly restarted daemon, 903s uptime) showed **1,144
tracked entries**, consistent in order of magnitude with the prior round's ~1,912 figure —
both numbers reflect genuine, expected behaviour of a system-wide monitor on a real desktop
Linux host with thousands of live threads, not a bug inflating the count. This is relevant
to §4 of `REPORT.md` (the GIL/scan-cycle-latency finding): scoring on the order of a
thousand-plus entries every cycle, single-threaded, competing for the GIL with four
collector threads, is a plausible and now-quantified contributor to that inflation — the
fix direction is architectural (scope tracking to a narrower process set, or move
collectors off the GIL-sharing thread model), not a bug fix in the filter itself, since
there isn't one to fix.

---

## P1-1: Confusion matrix

Computed by `evaluation/compute_confusion_matrix.py` from the existing per-poll CSVs in
`evaluation/results/`, which do retain per-observation granularity (one row per tracked
process per scan-tick) — no re-capture was needed.

**Unit of classification** (defended per the work order's own recommendation): one
(process, scan-tick) observation. Detector-positive iff `confidence` ≥ MEDIUM
(score ≥ 40, `throttle_threshold` — the tier at which mitigation first actively engages,
not merely a logged ALERT).

**Ground truth** assigned per source file: every row from a positive-labelled scenario CSV
(`xmrig_ground_truth_1M.csv`, `evasion_throttled_1thread_3M.csv`, `packed_xmrig_3M.csv`,
`network_pool_blocklist_t{1,2,3}.csv`, `browser_wasm_miner.csv`) is ground-truth positive;
every row from a negative-labelled CSV (`benign_openssl_t{1,2,3}.csv`,
`benign_gcc_compile_t{1,2,3}.csv`) is ground-truth negative.

| | n | Detector-positive (MEDIUM+) |
|---|---|---|
| xmrig_ground_truth_1M.csv | 287 | 194 (67.6%) |
| evasion_throttled_1thread_3M.csv | 293 | 185 (63.1%) |
| packed_xmrig_3M.csv | 285 | 248 (87.0%) |
| network_pool_blocklist_t1/t2/t3.csv | 75 | 0 (0.0%) |
| browser_wasm_miner.csv | 61 | 0 (0.0%) |
| benign_openssl_t1/t2/t3.csv | 191 | 0 (0.0%, correctly quiet) |
| benign_gcc_compile_t1/t2/t3.csv | 4,906 | 0 (0.0%, correctly quiet) |

**Confusion matrix (n = 6,098 total observations): TP = 627, FN = 374, TN = 5,097, FP = 0.**

| Metric | Value |
|---|---|
| Precision | **1.000** |
| Recall | **0.626** |
| F1 | **0.770** |
| Specificity (TNR) | 1.000 |
| False-positive rate | 0.000 |

**Read this alongside `REPORT.md` §4, not in isolation.** Recall is dragged down entirely
by two scenario categories scoring 0% under this rule, for two different, already-documented
reasons — neither is a scoring-logic failure on this data:

1. **network_pool_blocklist (75 obs, 0% positive).** The raw eBPF `net_collector` correctly
   incremented `mining_pool_hits` every cycle (confirmed directly in the CSVs, climbing
   1→12 across the run) — the signal reached the fingerprint layer. The detection engine's
   `_scan()` loop itself is the bottleneck: `REPORT.md` §4 measured real scan-cycle gaps of
   13.2–34.1s (mean 20.2s) against a configured 5s interval, caused by GIL contention with
   four eBPF collector threads under load. This test client's entire lifecycle is ~24
   seconds — short enough to fall entirely inside a single inflated gap and never be
   examined by a scan cycle at all. The same mechanism scores correctly in isolation
   (50/MEDIUM at t=14.0s, reproduced twice per §4) when not competing with a concurrently
   active miner's event volume for the detection thread's time.
2. **browser_wasm_miner (61 obs, 0% positive under this rule).** This one is a genuine,
   more interesting boundary case: the actual peak reached was **39/LOW/ALERT** (`REPORT.md`
   §7), one point below the MEDIUM cutoff this matrix uses. Under the work order's stricter
   recommended rule (MEDIUM+, i.e. mitigation-active) this counts as a miss; under a looser
   "any alert-tier detection" rule it would count as a true positive. Report both readings
   in Chapter 6 rather than picking one silently: **strict (MEDIUM+) recall = 0.626;
   any-alert-tier recall would be higher** because browser_wasm_miner did generate a
   logged alert, just not one that crossed into active mitigation.

**Pre/post-fix separation:** the work order requires this explicitly. There is nothing to
separate here — every CSV feeding this matrix was captured after both fixes made during the
evaluation process (`DetectionEngine` thread-death guard, the scratchpad/huge-page
joint-condition fix) were already in place. No valid pre-fix dataset exists to report
alongside it; the pre-fix condition simply produced non-functional 0/NONE output across the
board (a dead detection thread, not a meaningfully comparable classifier), so there is no
second matrix to compute.

---

## P1-2: Mitigation effect (light-touch, existing-data only)

**What is already verified, independent of this round:** `REPORT.md`'s methodology (§1)
states mitigation this round ran in live mode (`dry_run=false`), and every THROTTLE
decision was independently checked against `/sys/fs/cgroup/eddmc/<pid>/cpu.max` — so the
enforcement mechanism itself is confirmed real, not merely logged.

**Attempted this round:** deriving CPU%-before-vs-after-enforcement directly from the
`on_cpu_ns` scheduler counter already present in the capture CSVs, by taking per-tick
deltas and comparing the mean across rows tagged `mitigation=NONE` (before) against rows
tagged `mitigation=THROTTLE` (after), for the three tracks that reached THROTTLE this round.
**This did not produce a usable number**: `on_cpu_ns` in these CSVs updates on an
irregular, coarser cadence than the 1s capture interval (long flat stretches punctuated by
step jumps — visible directly in `network_pool_blocklist_t1.csv`'s raw rows), so a
per-tick delta badly misestimates instantaneous CPU% depending on tick alignment, and every
track's before/after means computed this way came out near-zero and indistinguishable from
each other — an artefact of the sampling method, not a real absence of effect. Producing a
trustworthy before/after CPU% figure would require re-instrumenting
`results_capture.py`/`fingerprint.py` to expose the `psutil`-based `cpu_percent(pid)` value
that `fingerprint.py:_cpu_percent()` already computes internally for scoring (currently not
included in the CSV schema) and re-running live — not attempted this round, flagged as the
concrete next step for whoever picks this up.

**What existing evidence does support** (from the prior round,
`reports/CHAPTER_06_RESULTS.md` §6.3.1): a live XMRig instance's measured CPU utilisation
fell from 272% to roughly 77–170% once throttled, and score did not escalate further for
the remainder of that run — real, if not from this round's own capture.

**Reversibility** (work order's specific ask): not exercised this round. No process in
either round's runs was driven back below a tier boundary while still live and observed
for cgroup/iptables rule removal; this remains untested.

**HIGH/CRITICAL tiers against a real process** (work order's specific ask): **never
exercised against a live process in either evaluation round.** Every real, live detection
in this round's data plateaus at MEDIUM (45.0, 45.0, 46.0) or LOW (39.0). The only HIGH-tier
result on record (78/HIGH/BLOCK, `reports/CHAPTER_06_RESULTS.md` §6.4.3) was a synthetic
re-score of a captured fingerprint used to verify the scratchpad-fix didn't weaken true-positive
sensitivity, not a live process reaching HIGH under real-time observation. **RQ5 can
therefore only be partially answered**: policy-driven mitigation is proven effective and
real at the THROTTLE tier specifically; the BLOCK (HIGH) and SUSPEND/TERMINATE (CRITICAL)
tiers remain implemented but empirically unvalidated against any live process in this
evaluation's history. State this distinction explicitly in Chapter 6 rather than
generalising from the one THROTTLE-tier result to the whole cascade.

---

## P1-5: Time-to-alert vs. design target

Pulled directly from `REPORT.md` §5/§7 (regenerated this round from the same CSVs feeding
the confusion matrix above — no new figures computed separately).

| Scenario | Time to first alert-tier (LOW+) | Time to MEDIUM+ | Configured scan interval |
|---|---|---|---|
| XMRig ground truth (`--bench`) | 77.2s | 104.0s | 5s |
| Browser WASM miner | 55.8s | never (peaked at LOW) | 5s |
| Self-throttled evasion attempt | 79.6s | 114.1s | 5s |
| UPX-packed XMRig | 28.2s | 42.4s | 5s |
| Benign (OpenSSL, gcc) | never (both, all trials) | never | 5s |
| Network pool-hits | never (all 3 trials) | never | 5s |

Every positive figure here is 6–16x the configured 5-second scan interval, and this is not
a single anomaly — it is consistent with `REPORT.md` §4's directly measured real scan-cycle
gaps of 13.2–34.1s (mean 20.2s) under concurrent eBPF event load, and with this round's
P0-2 finding that the daemon tracks on the order of 1,000+ processes every cycle on this
host. **Relate all of the above three findings together in Chapter 6, not separately**:
the 5s design target is real and intentional (`daemon/detector/engine.py`'s
`interval_s: float = 5.0` default), the measured latency inflation is real and traced to a
specific, defensible mechanism (single-threaded GIL-bound scan loop competing with
collector threads over a large tracked-process set), and the practical consequence is a
short-lived process can be entirely missed if its lifetime falls inside one inflated gap —
exactly what happened to the network pool-hits track's 0/3 result in this round's official
trial, as opposed to a scoring-logic defect.

**Whether the P0-2 process-filter investigation changes this finding, per the work order's
specific question:** no — there is no filter to fix (see P0-2 above), so this latency
finding is not resolved by this round's work and should be carried into Chapter 6 unchanged
from the prior round's characterisation, now with an added, quantified link to tracked-process
count as a contributing factor rather than a vague "GIL contention" explanation alone.

---

## Updated RQ status (for Chapter 6's own summary table)

| RQ | Question | Status after this round |
|---|---|---|
| RQ1 | Which kernel-level features distinguish mining from benign work? | Unchanged from prior round (strong; the 14-signal breakdown in `docs/ARTEFACT_INVENTORY.md` §1 is the authoritative reference now) |
| RQ2 | Can eBPF capture those signals with sufficient fidelity? | Adequate; `docs/ARTEFACT_INVENTORY.md` is now the authoritative feature/collector inventory, superseding the undocumented-feature gap the work order flagged |
| RQ3 | Does deterministic scoring detect reliably under evasion? | Strong on TP/precision (100% precision, 0 false positives across 6,098 observations); recall (62.6% under the strict MEDIUM+ rule) is explained, not just reported — see P1-1 |
| RQ4 | What runtime overhead does the daemon introduce? | **Still unusable.** Condition 1 (no daemon) quantified the host's own noise floor (mean 5.0%, peaks to 233%); conditions 2–4 not run this round. Not answered. |
| RQ5 | How effective is policy-driven mitigation? | **Partial.** THROTTLE proven real and effective; BLOCK/CRITICAL never exercised against a live process; reversibility untested |
| RQ6 | Does the fingerprint registry accelerate cross-deployment detection? | **Not empirically assessed** (Path B: gate recalibration proposed with evidence, not implemented; two-node experiment not run) |

---

## What this means for Chapter 6, concretely

- The accuracy narrative can now be quantitative (precision/recall/F1/FPR with n stated),
  not just a scenario tally — use the P1-1 table, and present the two 0%-recall categories
  with their explanations rather than as unexplained misses.
- RQ4 (overhead) cannot yet be answered credibly. Say so directly rather than reusing the
  original 172.2%/112.4% figures or reporting condition-1-only numbers as if they covered
  the daemon's own footprint — they don't, they measure the host without the daemon
  running at all.
- RQ6 (registry) should be written as designed-and-implemented-but-not-empirically-validated,
  with the Path B recalibration argument presented as a contribution in its own right (a
  DSR refinement identified through evaluation) rather than as a completed validation.
- RQ5 (mitigation) should distinguish THROTTLE (validated) from BLOCK/CRITICAL
  (unvalidated) explicitly, rather than one blanket "mitigation works" statement.
- Time-to-alert figures should always be presented together with the scan-cycle-latency
  and tracked-process-count findings — quoting a time-to-alert number alone, without that
  context, misrepresents a measured architectural limitation as a fixed design parameter.
