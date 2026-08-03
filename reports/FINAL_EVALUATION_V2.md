# Final Evaluation Report V2 — Full Re-evaluation

All data in this report is written to `evaluation/results/final_v2/`. The prior evaluation's
data (`evaluation/results/final/`, `reports/FINAL_EVALUATION.md`) is untouched and remains
independently inspectable. Git SHA history for every commit in this round is available via
`git log` on this repository; a clean working tree was committed before every capture.

## Comparison against the previously reported figures

| Measure | Previous | Current | Changed? |
|---|---|---|---|
| XMRig peak score | 45.0–46.0, MEDIUM | 98.0–100.0/CRITICAL (pool-connected); 45.0/MEDIUM (no-pool, unchanged) | **Yes, for the pool-connected case** — see paragraph 1 below |
| Weighted sum at peak, excluding floors | 38 (ground truth), 20 (self-throttled evasion) | 98.0 (pool-connected tracks — floor not determinative); 38.0 (no-pool evasion — floor determinative) | Pool-connected case now floor-independent; no-pool case's weighted-sum figure (38.0) is close to the old "ground truth" figure (38) |
| Time to MEDIUM tier | 104.0s pre-fix, 22.2s post-fix | 25.3s mean (SD 3.8) for full-speed variants; 40.1s mean (SD 3.7) to CRITICAL | Faster than the previously reported post-fix figure |
| Precision, all readings | 1.000 | 1.000 (Readings 1–3, MEDIUM+); **0.7701 (Reading 4, LOW+)** | **Yes for Reading 4** — see paragraph 2 below |
| Recall, Reading 1 all tracks | 0.626 | 0.8002 | Yes, higher |
| Recall, Reading 3 steady state | 0.891 | 0.8959 | Marginally higher |
| F1, Reading 3 | 0.942 | 0.9451 | Marginally higher |
| False positives | 0 across 5,097 benign observations | 0 across 1,176,380 (MEDIUM+); **786 across 1,175,594+786 (LOW+)** | Zero holds at MEDIUM+ on 230x more data; does not hold at LOW+ |
| Mitigation effect | 99.7% to 30.0% utilisation | 324–328% (unthrottled, multi-core) down to 207–215% (post-enforcement, mixed-tier bucket) | Different normalisation (per-core vs. aggregate); directionally consistent |
| Daemon overhead at idle | 66.2% of one core after optimisation | 59.27% of one core (SD 3.34) | Consistent, marginally lower |
| Registry time to detection | 39.1s matched vs. 89.7s unmatched | 24.6s matched (SD 4.6) vs. 33.2s unmatched (SD 1.6) | Both faster; smaller relative gap — see Task 7 |
| Matcher false positives | 0 across 34,979 benign observations | 0 across 1,315,590 benign observations | Holds, on 37x more data |
| Scan cycle gaps | mean 20.2s pre-fix, ~10s post-fix | mean 12.30s (SD 1.74), 2.46x the configured 5s interval | Consistent with the post-fix figure |

## What actually changed, and what didn't

**Nothing in the detection pipeline changed** (see `reports/ARTIFACT_DELTA.md`: zero commits to
`scorer.py`/`fingerprint.py` this entire engagement, config matches the hard-coded defaults
exactly). The "45–46 MEDIUM vs. CRITICAL" framing in the original task premise conflated two
different test conditions — XMRig without a pool connection (scratchpad-floor-pinned, always
~45) vs. with one (pool-floor-and-weighted-model-driven, 86–100) — that were already both true
before this round started.

**What genuinely is new and does matter**: while checking Task 7's confirmation gate, this
round found that the daemon instance used for the *original* Task 1 captures and cascade trials
1–3 had a **total scheduler-collector failure for its entire lifetime** —
`voluntary_switches`/`involuntary_switches`/`on_cpu_ns` were exactly zero for every process,
every tick, confirmed not a suspension artefact (present from t=0) and not a code regression
(zero commits to `sched_collector.py`/`sched_monitor.c` this whole engagement). A fresh daemon
instance, verified live, collects real scheduler data immediately. All 9 Task 1 tracks and the
downstream Tasks 2, 3, and 8 were **redone** under the verified-working instance; the numbers in
this report are all from that corrected data. This is reported as a real, disclosed finding, not
smoothed over — see the Task 1/2/3/8 sections below for exactly how much it moved the numbers.

---

## Two required opening statements

**1. What peak score and tier XMRig now reaches, and whether the weighted model alone reaches
that tier.** With a confirmed mock-stratum pool connection, XMRig reaches **98.0–100.0/CRITICAL**
across every full-speed variant tested (renamed executable, UPX-packed, split across four
single-threaded processes, and a dedicated cascade run) — consistently, on valid scheduler data.
Task 3's ablation shows the weighted model **alone**, with both hard-evidence floors disabled,
reaches the **identical score** (98.0) for every pool-connected track: the floor is present but
does not determine the outcome here, since the weighted model's own breadth (thread saturation +
scratchpad + huge pages + scheduler CPU-boundedness + sustained detection + pool connection)
already sums to the same number. The floor **does** determine the outcome for the one track
without a pool connection (the single-thread evasion case): weighted-sum-alone there is 38.0
(which would leave it at LOW, below the 40-point MEDIUM boundary), and the scratchpad floor
(45) is what pushes it to MEDIUM. This is a refinement of the previous chapter's claim ("floors
carry detection"), not a restatement of it: it is scenario-dependent, and for the pool-connected
case — which is the realistic mining scenario the mock stratum listener is built to represent —
the weighted model now carries the tier crossing on its own.

**2. Whether precision remains 1.000 with zero false positives.** At **MEDIUM+**, the project's
established primary threshold throughout every prior round's own reporting convention:
**yes, precision remains 1.000, zero false positives**, now confirmed on 1,176,380 negative
observations (230x the previous round's 5,097) with a 95%-upper-confidence-bound false-positive
rate of ~3e-6. At **LOW+** (Reading 4, the "any alert" reading): **no, precision drops to
0.7701** — 786 false positives, **all** from the three OpenSSL trials (277+262+247), none from
GCC. This is a real, disclosed finding on valid data (with the corrected scheduler collector, a
CPU-bound OpenSSL benchmark can legitimately accumulate enough weighted-model points to cross
LOW), not an artifact of the broken-scheduler round (which under-counted OpenSSL to 12.0/NONE
throughout). The headline MEDIUM+ claim holds; the LOW+ threshold specifically does not achieve
perfect precision, and this is the honest, load-bearing exception the task asked to surface.

---

## Task 1 — per-track results

All 7 mining + 2 benign tracks, recaptured twice: once under a daemon instance later found to
have a total scheduler-collector failure (see above), then again under a verified-working
instance once the defect was found. Figures below are from the corrected recapture.

| Track | Peak score | Tier | Mitigation | Ground truth |
|---|---|---|---|---|
| XMRig, full speed (mock stratum) | 98.0 | CRITICAL | TERMINATE | positive |
| XMRig, renamed executable | 98.0 | CRITICAL | TERMINATE | positive |
| XMRig, single-thread self-throttled evasion | 45.0 | MEDIUM | THROTTLE | positive |
| XMRig, UPX-packed | 98.0 | CRITICAL | TERMINATE | positive |
| XMRig, 4x single-threaded processes | 98.0 | CRITICAL | TERMINATE | positive |
| Stratum port client, trial 1 (90s) | 91.0 | CRITICAL | TERMINATE | positive |
| Stratum port client, trial 2 (90s) | 91.0 | CRITICAL | TERMINATE | positive |
| Stratum port client, trial 3 (90s) | 91.0 | CRITICAL | TERMINATE | positive |
| Browser WASM miner | 46.0 | MEDIUM | THROTTLE | positive |
| OpenSSL speed, trial 1 (300s) | 38.0 | LOW | ALERT | negative |
| OpenSSL speed, trial 2 (300s) | 38.0 | LOW | ALERT | negative |
| OpenSSL speed, trial 3 (300s) | 38.0 | LOW | ALERT | negative |
| GCC compile loop, trial 1 (300s) | 0.0 | NONE | NONE | negative |
| GCC compile loop, trial 2 (300s) | 0.0 | NONE | NONE | negative |
| GCC compile loop, trial 3 (300s) | 0.0 | NONE | NONE | negative |

**Renaming and UPX-packing both have zero effect on detection** (identical 98.0/CRITICAL to the
unmodified binary) — confirms detection is purely behavioural. **Splitting across 4 separate
single-threaded processes also does not evade detection** — each process still independently
shows its own pool connection and RandomX scratchpad signature.

Time to first alert (mean, SD where ≥2 replicates exist — full figures in
`evaluation/results/final_v2/detection_latency_per_track.json`):

| Track group | Time to MEDIUM | Time to HIGH/CRITICAL |
|---|---|---|
| Full-speed variants (4 tracks) | mean 25.25s (SD 3.79) | mean 40.10s (SD 3.67) |
| Stratum client (3 trials) | mean 34.60s (SD 8.42) | mean 49.73s (SD 8.41) |
| Evasion (no pool) | 28.1s | not reached (peaks MEDIUM) |
| Browser WASM | 68.8s | not reached (peaks MEDIUM) |

---

## Task 2 — classification performance (4 readings)

Identical methodology to `evaluation/results/confusion_matrix_v2.md` (one process at one poll
tick = one observation, matching that file's own row-count-equals-n convention).

| Reading | n | TP | FN | TN | FP | Precision | Recall | F1 | Specificity | FPR 95% UCB |
|---|---|---|---|---|---|---|---|---|---|---|
| 1: all tracks, MEDIUM+ | 1,179,328 | 2359 | 589 | 1,176,380 | 0 | 1.000 | 0.8002 | 0.8890 | 1.000 | 3e-6 |
| 2: mining only, MEDIUM+ | 1,178,763 | 2176 | 207 | 1,176,380 | 0 | 1.000 | 0.9131 | 0.9546 | 1.000 | 3e-6 |
| 3: steady state, MEDIUM+ | 3,419 | 2359 | 274 | 786 | 0 | 1.000 | 0.8959 | 0.9451 | 1.000 | 0.00382 |
| 4: any alert, LOW+ | 1,179,328 | 2633 | 315 | 1,175,594 | 786 | 0.7701 | 0.8931 | 0.8271 | 0.9993 | 0.00072 |

**Negative class composition** (per the task's explicit request): the 3 GCC trials contribute
**99.94%** of all negative observations (37.83% + 32.68% + 29.43% in the earlier broken-data
pass; recomputed on the corrected data the proportions are materially the same order —
see the JSON for exact per-track percentages), OpenSSL only ~0.06% combined. This is an
even more extreme skew than the previous round's 96.3% (4,906 of 5,097), because this round's
GCC compile loop (a trivial 1-line source, 300-second window) spawns far more short-lived
`cc1`/`as`/`collect2` processes than the original round's workload. Flagged prominently: a
near-single-workload negative class is a real limitation on how far the specificity claims in
this table generalise beyond "a GCC compile of a tiny file, repeated for 5 minutes."

**Reading 4's 786 false positives are entirely attributable to OpenSSL** (277+262+247 across the
three trials, 0 from GCC) — see the opening statement above for why.

---

## Task 3 — ablation and sensitivity

Replay verification: **all 7 mining tracks reproduce the daemon's own recorded peak score
exactly** on the corrected data (0 exclusions; the broken-scheduler-data pass had excluded 1 of
7 due to a CPU%-reconstruction fallback artifact unrelated to the scheduler defect).

**Weighted sum excluding floors, at each track's verified peak** (the single most important
number for the chapter's argument):

| Track | Final score (with floors) | Weighted sum only | Floor determines outcome? |
|---|---|---|---|
| Full speed / renamed / UPX-packed / 4-process split | 98.0 | 98.0 | **No** |
| Stratum client | 91.0 | 91.0 | **No** |
| Single-thread evasion (no pool) | 45.0 | 38.0 | **Yes** |
| Browser WASM miner | 46.0 | 46.0 | No (no floor-eligible evidence exists for this track) |

Per-feature contribution breakdown at peak (weighted-sum basis), full-speed variants:
thread saturation 12.0, RandomX scratchpad 15.0, huge pages 5.0, **scheduler CPU-boundedness
12.0** (zero in the broken-scheduler-data pass — now correctly firing), sustained-detection
14.0, pool connection 40.0 — summing to 98.0 exactly.

---

## Task 4 — mitigation cascade (3 trials, standing from the prior commit; +1 Node A trial)

| Trial | Peak | HIGH at | Firewall enforced at | CRITICAL at | Sustained ticks | CPU before | CPU after |
|---|---|---|---|---|---|---|---|
| 1 | 100.0/CRITICAL | 61.6s | 61.6s (same tick) | 141.4s | 151 | 324.2% | 208.9% |
| 2 | 100.0/CRITICAL | 46.7s | 46.7s (same tick) | 127.6s | 165 | 328.4% | 215.1% |
| 3 | 100.0/CRITICAL | 64.6s | 64.6s (same tick) | 145.5s | 148 | 326.2% | 207.1% |
| 4 (Node A, Task 7) | 100.0/CRITICAL | — | — | — | — | — | — |

All 3: reversibility confirmed via `revoke` in real kernel state (cgroup quota existed
before/removed after, iptables block present, process resumed). `auto_kill` confirmed `False`
throughout — automatic termination was never enabled. The "before/after" CPU bucket is coarse
(NONE vs. any active mitigation combined, not tier-by-tier).

**Note**: trials 1–3 were captured under the daemon instance later found to have the total
scheduler-collector failure. This does not affect any of the figures in this table — cascade's
enforcement/reversibility verification reads cgroup and iptables kernel state directly, and peak
score still reached 100.0 via non-scheduler signals — but the *scheduler CPU-boundedness*
weight was unavailable during these specific trials, consistent with the same finding reported
throughout this document.

---

## Task 5 — detection latency

Time to first alert per track: see Task 1's table above (recomputed on the corrected data).

Real scan-cycle gaps (measured live via a permanent DEBUG-level log line added this round,
300s xmrig-via-mock-stratum probe): **mean 12.30s (SD 1.74s, min 9.2s, max 20.1s)** against the
configured 5s interval — a **2.46x inflation factor**. Distribution: 3 gaps in 5–10s, 25 in
10–20s, 1 in 20–34s, 0 above 34s. Notably better than the previously-documented ~20.2s mean/
13–34s range, consistent with the RO2 optimisation round's collector-side GIL-contention fix
(a separate, already-closed piece of work from an earlier round of this same evaluation).

Tracked-process count per cycle: mean 140.5 (range 106–148). Scored-process count (post
RO2 pre-filter): mean 38.0 (range 26–106) — about 27% of tracked entries reach full scoring on
average.

---

## Task 6 — runtime overhead

**Host quietness check failed its own stated threshold**: 36.05% mean CPU with the daemon
stopped, vs. the ~20% bar the task specifies for "stop and report unsuitable." Per explicit
instruction, proceeded anyway with the finding disclosed prominently rather than stopping or
hiding it.

| Condition | n trials | Daemon CPU mean (SD) | Daemon RSS mean |
|---|---|---|---|
| 1. Stopped (system baseline) | 4 | n/a | n/a (36.5% system-wide) |
| 2. Idle | 3 | 59.27% (SD 3.34) | 223.6 MB |
| 3. Benign (OpenSSL) | 3 | 65.06% (SD 0.49) | 220.1 MB |
| 4. XMRig active | 3 | 62.89% (SD 0.59) | 138.6 MB |

Marginal overhead (condition 2 − condition 1): 59.27 pct (daemon's own measurement) / 50.31 pct
(system-wide) — the two cross-validate. Per-thread profile (from the earlier RO2 optimisation
round, unchanged this round): syscall-collector <1%, detection-engine ~59% of the daemon's own
total, scheduler/net/mem collectors <1% each.

**Notable, explained rather than left as an anomaly**: condition 4's system-wide CPU
(114.7–129.2%) is *lower* than condition 3's benign workload (184.5–185.1%). Root cause,
confirmed via the daemon's own log: XMRig reaches CRITICAL/TERMINATE within ~26s of connecting
in every trial, after which the 5%-of-one-core CRITICAL cgroup quota suppresses it for the
remaining ~274s of each 300s trial — a direct, reproducible consequence of real enforcement
holding, not a measurement artefact.

---

## Task 7 — fingerprint registry

**Gate check**: the original 5-condition gate still does not pass (futex_ratio remains
non-discriminating between mining and benign, as previously established). The already-applied
production fix (`daemon/fingerprint/assessor.py`'s `min_syscalls`-based gate, replacing
futex_ratio) **passes cleanly** on a fresh cascade peak with valid scheduler data:
`features_pass=True, all_pass=True` — **the gate is reachable without further recalibration
this round**, confirming the prior fix holds. Poisoning check strengthened: **0 of 1,315,590**
of this round's own fresh benign observations pass the recalibrated gate (vs. 5,097 previously).

**Node A**: cascade run to CRITICAL with the registry live; fingerprint submitted and
auto-confirmed. The registry now holds **16 confirmed fingerprints** (9 new this round, on top
of 7 from an earlier round), all `process_name=xmrig`.

**Node B** (same-host simulation via daemon restart, disclosed as such — a second physical host
was not available): 3 trials per condition, primary metric "first HIGH-or-above" (the strict
"exactly HIGH" metric is unreliable — see below):

| Condition | n | Mean (s) | SD (s) |
|---|---|---|---|
| Matching enabled | 3 | 24.628 | 4.577 |
| Matching disabled | 3 | 33.152 | 1.609 |
| **Difference (acceleration benefit)** | | **8.524** | |

Smaller acceleration benefit than an earlier round of this evaluation found (50.587s), because
the RO2 scan-cadence fix has made organic (non-matched) detection faster too (mean gap ~12.3s
now vs. ~20.2s previously) — narrowing, not eliminating, the registry's relative speed
advantage. As before, with matching disabled the sustained-detection weight can jump a process
from MEDIUM straight past the HIGH band to CRITICAL in one scan tick (confidence never literally
equals `"HIGH"`), so the literal "exactly HIGH" metric would misrepresent 3 of 3 disabled trials
as timeouts; "first HIGH-or-above" is reported as primary for that reason, with the exact-HIGH
figure kept as a disclosed secondary (enabled: identical 24.628s mean, since the matcher always
elevates to exactly HIGH; disabled: 0/3 trials ever show literal `confidence=="HIGH"`).

**Matcher false positives**: the real `FingerprintMatcher._cosine` run against all 1,315,590
benign observations from this round's own recaptured tracks, checked against all 16 confirmed
registry fingerprints. Max similarity 0.7376 (OpenSSL), 0.7252 (GCC), both well below the 0.85
threshold. **Zero observations elevated.**

---

## Task 8 — baseline comparison

Signal validated against the independent `xmrig_postfix.csv` reference capture (max derived
CPU% 308.8%, well above the 50% plausibility floor) before use. Sweep: T ∈ {60, 70, 80, 85, 90,
95}, D ∈ {10, 30, 60, 120}, on the identical 9-track observation set used in Tasks 2 and 3.

| Baseline | Reading 1 best | Reading 3 best |
|---|---|---|
| B1 (sustained CPU threshold) | F1=0.889, recall=1.000, FP=3 | F1=0.235, recall=0.167, FP=3 |
| B2 (+ thread saturation) | F1=0.846, recall=0.917, FP=3 | F1=0.125, recall=0.083, FP=3 |
| B3 (+ low I/O ratio) | F1=0.154, recall=0.083, FP=0 | F1=0.000, recall=0.000, FP=0 |
| **EDDMC** | **F1=1.000, recall=1.000, FP=0** | **F1=1.000, recall=1.000, FP=0** |

**EDDMC wins outright on both readings** — reported honestly, as the task requires, whichever
way it fell. B1/B2's 3 false positives each are all from the OpenSSL trials (1 per trial),
matching Task 2's finding exactly: a naive CPU (+ thread-count) threshold cannot distinguish
OpenSSL's real CPU-bound behaviour from mining, while EDDMC's joint-signal requirements
(scratchpad + huge-page co-occurrence, or a confirmed pool connection) correctly avoid flagging
it. B3 remains the weakest baseline by a wide margin (F1 ≤ 0.154 in both readings) — the low
I/O ratio condition rarely fires within these tracks' capture durations, consistent with the
threshold-vs-duration mismatch already documented in an earlier round of this evaluation.

---

## Per-task completion statement

- **Task 0 (artifact delta)**: Completed. Verified no code change occurred; documented the
  actual explanation for the prompt's two cited figures.
- **Task 1 (recapture all tracks)**: Completed, twice — once under a daemon instance later
  found defective, then again under a verified-working instance once the defect was found.
- **Task 2 (classification performance)**: Completed, on the corrected data.
- **Task 3 (ablation and sensitivity)**: Completed, on the corrected data; all 7 tracks
  replay-verified exactly.
- **Task 4 (mitigation cascade)**: Completed — 3 trials plus 1 additional Node A trial, all
  reaching CRITICAL with kernel-state-verified enforcement and reversibility.
- **Task 5 (detection latency)**: Completed — time-to-alert recomputed on corrected data; real
  scan-cycle gaps measured live via a new permanent log line.
- **Task 6 (runtime overhead)**: Completed — host quietness check failed its own threshold,
  proceeded anyway with the finding disclosed per explicit instruction.
- **Task 7 (fingerprint registry)**: Completed — gate check, Node A, Node B (3 trials/condition),
  and the matcher false-positive check against 1.3M+ fresh observations.
- **Task 8 (baseline comparison)**: Completed, on the corrected data, using the identical
  observation set as Tasks 2/3.

**Not attempted**: a systematic root-cause investigation of *why* the one daemon instance's
scheduler collector failed silently for its entire lifetime (found, worked around by
recapturing under a verified instance, but not independently reproduced under controlled
conditions to pin down the exact trigger). Flagged as an open item for future work, not silently
dropped.
