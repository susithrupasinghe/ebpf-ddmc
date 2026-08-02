# Final Evaluation Report (RO2 / RO4 / RO6 / RO7 closure round)

Supersedes the previous version of this report, which marked RO2, RO6 and RO7 "Met" on
evidence that did not support it (RO2: measuring 163.6% CPU at idle is not the same as
proving the daemon lightweight; RO6: the baseline comparison used 4 of 7 tracks with an
empty per-track FP breakdown; RO7: the two-node experiment was skipped by misapplying a
stop condition). This version applies the numeric pass criteria below literally: an
objective is marked Met only if its stated criterion is satisfied by the evidence cited.
RO4 already closed properly in the prior round and is carried forward unchanged.

Git SHA at report time: `64ab129`. Working tree clean at every measurement in this round
(commits made before each run; see git log for the full sequence).

## 1. Status table

| RO | Criterion | Achieved | Met? |
|---|---|---|---|
| RO2 | Marginal daemon CPU overhead at idle < 25% of one core, RSS < 150 MB (mean, ≥3 trials) | 66.2% of one core (SD 0.64, n=3, 60s/trial), RSS 219.1 MB (n=3) | **Partially met** |
| RO4 | CRITICAL reached, enforcement verified in kernel state, reversibility confirmed | Yes — 3 trials prior round + 1 re-verification trial this round, all consistent | **Met** |
| RO6 | All 7 tracks recaptured, all 3 baselines produce finite metrics, non-empty per-track FP breakdown | 7/7 tracks recaptured; B1/B2/B3 all finite; FP breakdown non-empty across the T×D sweep | **Met** |
| RO7 | Time-to-detection with/without fingerprint matching, ≥3 trials/condition, mean+SD both | Enabled: mean 39.105s (SD 5.401, n=3). Disabled: mean 89.692s (SD 7.986, n=3). Difference: 50.587s | **Met** |

Three of four objectives close on literal evidence this round. RO2 does not: real, verified
optimisation work cut idle overhead by roughly 60% relative (163.6% → 66.2% of one core),
but the stated <25% target is not reached. That is reported as a partial result, not
reframed as success.

---

## 2. RO2 — daemon overhead: profiling, optimisation, re-measurement

### 2.1 Profiling (confirms the working hypothesis was wrong)

Direct per-thread CPU-time sampling (`/proc/<pid>/task/<tid>/stat`, 60s window, idle host,
pre-optimisation code) attributed the daemon's overhead as follows:

| Thread | CPU (% of one core) |
|---|---|
| syscall-collect | 95.8 |
| detection-engine | 42.4 |
| sched-collector | 25.9 |
| net-collector, mem-collector, alert-bus, ipc-server, main | <1 each |
| **Total** | **164.9** |

The task's own working hypothesis — that collectors are cheap and the Python scoring loop
is the cost driver — is **refuted** by this measurement: the syscall collector alone cost
more than double the detection engine. Root cause, confirmed by reading
`daemon/ebpf/syscall_monitor.c` directly: the `raw_syscalls/sys_enter` tracepoint fires on
every syscall from every process on the host (zero filtering, a previously-documented
finding) and used to `perf_submit()` a full event for each one, driving a Python-side
perf-buffer callback at that same host-wide rate. A full-repo grep confirmed the data this
built (`syscall_events`, a raw per-syscall list) was never read anywhere outside the
collector itself except to be stripped back out before API serialisation — write-only dead
computation.

### 2.2 Two fixes implemented

1. **Removed the dead perf-event channel.** `syscall_monitor.c`'s `perf_submit()` call and
   the corresponding Python-side `open_perf_buffer`/`perf_buffer_poll`/`_on_syscall_event`
   path in `syscall_collector.py` were deleted entirely. The BPF hash-map poll
   (`_poll_bpf_maps`) already independently maintains every counter the scorer consumes,
   aggregated in-kernel — zero detection-logic effect, confirmed by the grep above.

2. **Scoring pre-filter** (`daemon/detector/engine.py`, `DetectionEngine._scan()`). A live
   6-second sample of the running store found 3,497 of 3,552 tracked entries (98.4%) had
   made precisely zero new syscalls — almost the whole population is dormant background
   system processes. A process is now admitted to `build_fingerprint()` + `Scorer.score()`
   only if:
   - its `total_syscalls` count increased since the last scan, **or**
   - it has ever registered a mining-pool connection, **or**
   - it already has an active mitigation tier.

   The last two conditions exist specifically to close the evasion loophole the task warned
   about: a miner cannot escape the filter by simply going CPU/syscall-idle, since a
   confirmed stratum connection or an active mitigation always forces a real score. Every
   process is still scored at least once, on first sighting. No scoring weight, floor, or
   tier boundary was changed. Tracked/scored counts per cycle are now exposed via
   `/api/status` (`engine_tracked`, `engine_scored`).

### 2.3 Post-fix profile and a secondary effect worth reporting honestly

Re-profiling under the same method (60s, idle) after both fixes:

| Thread | CPU (% of one core) |
|---|---|
| syscall-collect | 0.1 |
| detection-engine | 59.3 |
| sched-collector | 0.7 |
| net-collector, mem-collector, alert-bus, ipc-server, main | <1 each |
| **Total** | **60.2** |

Collector-side cost fell almost to zero, exactly as the dead-code removal predicted. The
detection engine's *share* rose (42.4% → 59.3%) even though its *total* CPU barely changed,
because removing the collectors' GIL contention lets the scan loop run close to twice as
often: a direct timestamp check showed scan gaps of ~10s post-fix versus the
previously-documented 13–34s (mean 20.2s) GIL-starved gaps pre-fix. Roughly double the scan
frequency offsets much of the pre-filter's per-scan saving. This is a **detection-latency
improvement**, not wasted optimisation work, and is reported as such rather than hidden.

### 2.4 Re-measured overhead, all 4 conditions, 3 trials × 60s each, same host

| Condition | Before (prior round) | After (this round) |
|---|---|---|
| 1. Stopped (system baseline) | 7.0% of one core | 36.1% of one core† |
| 2. Running, idle | 163.6% CPU (SD 2.7), 232.8 MB RSS | **66.2% CPU (SD 0.64), 219.1 MB RSS** |
| 3. Running, benign workload | 153.3% CPU, 234.9 MB RSS | 64.0% CPU (SD 2.62), 217.6 MB RSS |
| 4. Running, XMRig active | 95.7% CPU, 228.7 MB RSS | 54.9% CPU (SD 3.68), 214.1 MB RSS |

† This round's host background load was higher than the prior round's (system-wide, not
daemon-attributable) — disclosed rather than hidden. The condition 2–4 `daemon_cpu_pct_mean`
figures are per-process `psutil` measurements isolated from system-wide load, so the
daemon-specific before/after comparison above remains valid despite the noisier baseline;
only the raw system-wide condition-1 number is not directly comparable round-to-round.

RSS improved only marginally (~6%) even though both fixes targeted CPU, not memory —
consistent with removing the `syscall_events` list (previously capped at 2,000 entries per
tracked pid) recovering some memory, while the bulk of RSS comes from elsewhere (Python/BCC
interpreter overhead) neither fix touched.

**Verdict: RO2 partially met.** Idle CPU overhead fell 163.6% → 66.2% of one core (~59.5%
relative reduction) via two real, verified fixes. The <25%/<150MB target is not reached.
Stated plainly per the task's own instruction: state the figure achieved, don't restate the
criterion.

### 2.5 Task 1.4 — mandatory detection-integrity re-verification (all three pass)

Re-run live against the optimised daemon; none regressed, so the optimisation stands:

- **Cascade**: peak score 100.0/CRITICAL reached (~t=48s). Reversibility test confirms real
  kernel-state enforcement both before and after revoke: `cgroup_quota_existed_before=true`,
  iptables block present before revoke, revoke API call succeeded with
  `cgroup_removed=true` and `proc_resumed=true`.
- **Self-throttled evasion** (`xmrig --bench=1M --randomx-mode=light -t 1`, matching the
  original postfix capture): peak 46.0/MEDIUM/THROTTLE this round vs. 58.0/MEDIUM/THROTTLE
  originally — same confidence tier, ordinary score variance, no regression.
- **Benign tracks, zero false positives** (MEDIUM+ is this project's established
  false-positive threshold throughout — see §4 below): `openssl speed -multi 4 sha256` (a
  harder, more CPU-saturating case than a plain single-threaded run) peaked at 31.0/LOW,
  safely below MEDIUM; a real gcc compile loop (`gcc -O2 -c`, tracked via a new `--comm`
  substring filter added to `capture` since compilation forks `cc1`/`as`/`collect2` under
  different pids than the wrapper shell) peaked at 0.0/NONE.

---

## 3. RO4 — cascade / policy-driven mitigation (unchanged, carried forward)

Three trials, prior round, all reached CRITICAL with cgroup + iptables + SIGSTOP
enforcement verified in kernel state (not the daemon's own log), reversibility confirmed via
`revoke`:

| Trial | Peak | First CRITICAL | Revoke: cgroup removed | Revoke: iptables removed | Process resumed |
|---|---|---|---|---|---|
| 1 | 100.0/CRITICAL | t=74.0s | True | True | True |
| 2 | 100.0/CRITICAL | t=58.9s | True | True | True |
| 3 | 100.0/CRITICAL | t=81.8s | True | True | True |

Re-verified this round (§2.5) with one additional trial post-optimisation: same result
(CRITICAL reached, enforcement + reversibility both confirmed in kernel state).

**Limitation carried forward (revoke-display gap):** across every trial, once `revoke`
lifted real cgroup/iptables/SIGSTOP enforcement, kernel state stayed clear for the rest of
the run — but the daemon's own displayed `mitigation` column kept reading
`CRITICAL`/`TERMINATE`. The underlying xmrig process resumes identical behaviour after
SIGCONT, so the *score* never drops; and since CRITICAL is the top tier, the engine's
tier-escalation check (which only re-fires `_on_mitigation()` on a strict increase) never
re-applies at the same tier. Reversibility of the **enforcement actions** is real and
durable; the **status display** does not reflect a revoked-but-still-scored-CRITICAL
process. A genuine observability gap, worth a mention in the dissertation's limitations,
separate from whether reversibility itself works (it does).

---

## 4. RO6 — baseline comparison, all 7 tracks

### 4.1 Track recapture

All 7 tracks now resolve to real post-fix-collector captures (previous round: only 4 of 7,
`browser_wasm_miner` and `network_pool_blocklist` marked "not recaptured"):

| Track | Ground truth | Recaptured this/prior round |
|---|---|---|
| xmrig_ground_truth | positive | postfix verification round |
| evasion_throttled_1thread | positive | postfix round |
| packed_xmrig (UPX) | positive | postfix round |
| network_pool_blocklist (×3 trials) | positive | **this round**, 90s/trial (see §4.2) |
| browser_wasm_miner | positive | **this round** |
| benign_openssl | negative | postfix round |
| benign_gcc_compile | negative | postfix round |

`browser_wasm_miner` recaptured but scores only 15.0/NONE — an honest, disclosed limitation
of the current detector (no RandomX scratchpad signature, no stratum-port network signal for
an in-page WASM hash loop), not a capture failure.

### 4.2 A second, related GIL-latency finding during recapture

The `network_pool_blocklist` track initially scored a reproducible 0.0/NONE at the original
20–30s capture duration despite strong underlying signal (`mining_pool_hits=1`,
`scratchpad_huge_allocs>0`, `cpu_bound_ratio>0.99`). Root-caused via a temporary diagnostic
(added, used, fully reverted — clean `git diff`) to the **same** documented GIL scan-latency
inflation cited in §2.1/2.3: a short-lived process can fall entirely inside one 13–34s
scan gap and never be scanned while alive. Not a new bug. Fixed for capture purposes with a
longer (90s) window, matching the margin cascade's own 300s runs already use: all 3 trials
then scored 91.0/84.0/84.0, all CRITICAL/TERMINATE.

### 4.3 B3 debugged (Task 3.2)

B3 (sustained CPU + low I/O ratio) previously reported `TP=0`, `recall=0.000`,
`precision=NaN` across the whole sweep. Debugged against real data
(`xmrig_postfix.csv`): `read`/`write` syscall counters are correctly populated and non-zero
throughout (132 reads, 6 writes, frozen after startup) — **not** the "unpopulated counter"
scenario flagged as a possible cause. The real cause: `io_ratio` decays from 0.14 to 0.075
over the 300s capture as `total_syscalls` grows against the frozen read/write count, but
never crosses B3's 0.02 cutoff within that duration — a genuine threshold-vs-duration
mismatch, not a broken detector. Separately, the metric convention was fixed: precision/
recall/F1/specificity now use the standard zero-division convention (0.0, not NaN, when the
denominator is 0 — matches scikit-learn's `zero_division=0`), so B3's real 0.000 recall
reports as a finite number instead of poisoning every metric with NaN.

### 4.4 Full comparison: T×D sweep, all 7 tracks, EDDMC on the same data

Sweep: T ∈ {60, 70, 80, 85, 90, 95}, D ∈ {10, 30, 60, 120}. EDDMC itself run through the
identical (track, pid) groups via the existing scorer-replay path (`replay_track`), not
reused from an older, differently-scoped confusion-matrix run — a true same-data comparison.

| Baseline | Reading 1 (all tracks, t=0) best | Reading 3 (steady state) best |
|---|---|---|
| B1 (CPU threshold) | T=80,D=10: TP=6 FN=1 **F1=0.923** recall=0.857 | T=60,D=10: TP=2 FN=4 F1=0.500 recall=0.333 |
| B2 (CPU + thread count) | T=60,D=10: TP=5 FN=2 F1=0.833 recall=0.714 | T=60,D=10: TP=1 FN=5 F1=0.286 recall=0.167 |
| B3 (CPU + low I/O) | F1=0.000 recall=0.000 (every T/D) | F1=0.000 recall=0.000 (every T/D) |
| **EDDMC (scorer replay)** | TP=6 FN=1 **F1=0.923** recall=0.857 | TP=6 FN=0 **F1=1.000 recall=1.000** |

All four (including EDDMC) produce finite metrics; `not_recaptured=[]` confirms every track
was used; the per-track FP breakdown is non-empty across the sweep (B1 shows
`benign_openssl: 2` at several looser T/D points, though not at its single best-F1 config;
B2/B3 never produce a false positive at any swept T/D).

**Reported honestly, as the task requires:** on Reading 1, EDDMC **ties** the naive B1
threshold exactly — both miss the same one track (browser_wasm_miner, for the reason in
§4.1). A trivial 80%-CPU-for-10s check matches EDDMC's headline recall on this dataset. The
real separation appears on Reading 3 (steady state, excluding each track's own
pre-first-alert window): EDDMC reaches perfect recall (1.000) while B1 collapses to 0.333.
This confirms the already-documented finding that most of the apparent Reading-1 recall gap
is detection **latency**, not a real miss, and that EDDMC's advantage over a naive
CPU-threshold heuristic is real once that latency is corrected for — not visible from
Reading 1 alone.

---

## 5. RO7 — distributed fingerprint registry

### 5.1 Packager mislabelling fixed

`daemon/fingerprint/packager.py`'s `FEATURE_NAMES` listed index 4 as `"thread_density"`, but
`feature_vector()` actually computes `min(thread_cpu_ratio, 2.0)` — the raw [0,2] ratio, not
the dissertation's normalised [0,1] `thread_density`. Renamed to `"thread_cpu_ratio"` to
match what is actually submitted (value unchanged, avoiding inconsistency with any
fingerprint already in the registry). `matcher.py` only consumes the numeric
`feature_vector()` array, so this has zero effect on cosine-similarity matching — verified
by inspection and confirmed end-to-end (§5.2).

### 5.2 Node A — cascade to confirmation

Cascade run to CRITICAL with the registry live: **7 fingerprints submitted and
auto-confirmed**, all `process_name="xmrig"`, `feature_names` correctly showing the fixed
`"thread_cpu_ratio"` label. Feature vectors sensible and mutually consistent:
`cpu_bound_ratio` 0.949–0.977, `thread_cpu_ratio` capped at 2.0, `cpu_percent` /
`randomx_signature` / `pool_hit` all 1.0.

### 5.3 Node B — time-to-detection, with vs. without fingerprint matching

A second physical host was not available; Node B is simulated by restarting the daemon
between conditions (a fresh process wipes `engine.py`'s in-memory temporal/process-store
state, giving genuinely no detection history) — disclosed here plainly as a same-host
simulation, not a true cross-host test.

Two related metrics were tracked. **Primary: first HIGH-or-above.** Reason: with matching
disabled, the sustained-detection weight can push a process from MEDIUM straight past the
whole HIGH band to CRITICAL in a single 5s scan tick (observed, reproduced in all 3 disabled
trials: score 55→84 in one tick, confidence never literally equal to `"HIGH"`). With
matching enabled, the registry-elevation path explicitly caps at HIGH
(`result.confidence = "HIGH"`, `engine.py`), so it never skips the tier. A strict
`confidence=="HIGH"` metric would therefore read several disabled-condition trials as
timeouts even though HIGH-or-above severity genuinely was reached — that would misrepresent
the comparison. The literal exact-HIGH metric is kept as a disclosed secondary figure.

| Condition | n | Mean (s) | SD (s) |
|---|---|---|---|
| Fingerprint matching **enabled** | 3 | 39.105 | 5.401 |
| Fingerprint matching **disabled** | 3 | 89.692 | 7.986 |
| **Difference (acceleration benefit)** | | **50.587** | |

Secondary (strict exact-HIGH): enabled mean=39.105s (identical to primary — the matcher
always elevates to exactly HIGH); disabled: 0/3 trials ever showed literal `confidence=="HIGH"` (all skipped straight to CRITICAL) — reported as a `timed_out` count for this metric, not folded into a misleading mean.

### 5.4 Matcher false positives (Task 2.3)

The real `FingerprintMatcher._cosine` run against every recaptured benign observation:

| Track | n observations | Max similarity | Mean similarity |
|---|---|---|---|
| benign_openssl | 1,072 | 0.6866 | 0.5867 |
| benign_gcc_compile | 33,907 | 0.7115 | 0.5219 |
| **Total** | **34,979** | | |

Threshold is 0.85. **Zero of 34,979 benign observations reach it** — both tracks' maxima sit
well below (0.71 and 0.69), with a comfortable margin. `any_benign_elevated=False`.

---

## 6. Limitations carried forward for the dissertation

1. **Revoke-display gap** (§3): after `revoke` lifts real enforcement, the daemon's status
   column continues to display CRITICAL, because the score does not fall and tier
   escalation only re-fires on a strict increase. Enforcement reversal is real; the status
   display does not reflect it.
2. **Stale-observation defect** (found during RO7 gate work, prior round): a process with
   only 177 syscalls across a 30-second capture was polled repeatedly and counted as 30
   separate confirmations. Fixed in the fingerprint-registry gate via the `min_syscalls≥500`
   floor (`daemon/fingerprint/assessor.py`), but noted here as a class of defect (frozen
   observations being over-counted) worth flagging as a general caveat on any tick-based
   confirmation count elsewhere in the system.
3. **GIL scan-latency inflation** (§2.1/2.3/4.2, first documented in an earlier round): the
   detection engine shares the GIL with the eBPF collector threads; even after this round's
   fixes, scan gaps (~10s) remain roughly double the configured 5s interval. A process
   living for less than about one scan gap can be missed entirely — mitigated in this
   evaluation's own captures by using longer durations, but a real limitation of the live
   daemon against very short-lived processes.
4. **Browser-based WASM miners are not well detected** (§4.1): the current signal set
   (RandomX scratchpad allocation, stratum-port connections) does not match an in-page WASM
   hash loop's behavioural profile. `browser_wasm_miner` scores 15.0/NONE — a real, disclosed
   detection gap for this specific miner class, not a measurement artefact.
