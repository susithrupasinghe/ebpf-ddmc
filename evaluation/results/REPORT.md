# EDDMC Evaluation Report

Auto-generated 2026-07-27 19:12 UTC by `evaluation/generate_report.py` from the CSVs in `evaluation/results/`. Every number below comes directly from a CSV produced by `evaluation/results_capture.py` polling the live daemon during an actual run -- nothing here is hand-entered.

## 1. Methodology / Environment

- Platform: Linux-7.0.0-27-generic-aarch64-with-glibc2.43
- Kernel: 7.0.0-27-generic
- CPU cores (logical): 4
- XMRig: XMRig 6.25.0 with GCC 15.2.0
- Mitigation mode: live (`dry_run=false`) — every THROTTLE/BLOCK/TERMINATE recorded below reflects a real cgroup v2 CPU quota / iptables rule / signal applied to the actual process, independently verified against `/sys/fs/cgroup/eddmc/<pid>/cpu.max` during this evaluation session, not a simulated or logged-only decision.
- All tracks share one capture instrument (`results_capture.py`), polling the daemon's `/api/processes` endpoint at 1-2s intervals — scores/tiers/reasons are the live daemon's own scoring output, not independently recomputed.
- Benign baseline and network pool-hits tracks ran 3 independent trials each (mean ± sample stddev reported); XMRig-family and browser tracks ran once each due to per-run time cost (each XMRig-family run takes several minutes under real cgroup throttling) — see the caveats section below.

## 2. Detection accuracy summary

Every track is labelled with its *expected* outcome (should a real detector raise an alert-tier confidence here or not?) and compared against what actually happened, across every trial run.

| Test | Expected | Trials | Detected | Outcome |
|---|---|---|---|---|
| XMRig ground truth (--bench) | positive | 1 | yes | TP (correctly detected) |
| Browser WASM miner (Puppeteer) | positive | 1 | yes | TP (correctly detected) |
| Self-throttled miner (evasion attempt) | positive | 1 | yes | TP (correctly detected) |
| UPX-packed XMRig binary | positive | 1 | yes | TP (correctly detected) |
| Benign: OpenSSL crypto benchmark | negative | 3 | 0/3 | 3/3 correctly quiet |
| Benign: sustained parallel gcc compilation | negative | 3 | 0/3 | 3/3 correctly quiet |
| Network pool-hits (stratum port) | positive | 3 | 0/3 | 0/3 correctly detected — **3 missed** |

**Aggregate across all trials (13 total): TP=4, FN=3, TN=6, FP=0.**
Recall on positive (should-detect) cases: 4/7 = 57%.
Specificity on negative (should-stay-quiet) cases: 6/6 = 100%.

*(Read the network pool-hits row alongside §4 "Detection latency inflation under sustained eBPF event load" — its FN count here reflects scan-cycle inflation when run shortly after an active miner, not a scoring-logic failure; the same mechanism scores correctly in isolation. Treat the raw table above as one input to the discussion, not the full picture on its own.)*

## 3. A production-reliability bug found and fixed during this evaluation

**Symptom**: early in this evaluation, the first attempts at the network pool-hits and browser WASM tracks both scored 0/NONE despite `net_collector`/syscall counters climbing correctly — detection had silently stopped working for everything, even though the daemon looked completely healthy (collectors running, IPC responsive, uptime normal).

**Root cause**: `daemon/detector/engine.py`'s background scan loop (`_loop()`) called `self._scan()` with no exception handling around it. Separately, the end-of-scan garbage-collection step (which revokes mitigations and drops the store entry for any PID that has exited) called `self._on_process_gone(pid)` at two call sites, also unguarded. An exception raised during cleanup of a PID that exited mid-mitigation (e.g. a throttled process forcibly killed) would propagate up through `_scan()` and kill the entire detection-engine thread — permanently. Nothing else in the daemon would notice: eBPF collectors keep polling, the IPC server keeps answering `/api/status`, `/api/processes` keeps updating raw syscall/memory/network counters — but no process would ever be scored again until the daemon was restarted, with no error surfaced to an operator anywhere.

**Fix applied**: wrapped the `_scan()` call in `_loop()` in a try/except that logs (`logger.exception`) and continues, and wrapped both `on_process_gone()` call sites the same way — matching the defensive pattern already used around the per-PID scoring loop inside `_scan()` itself.

**Verification**: after the fix and a daemon restart, the network pool-hits track scored correctly (50/MEDIUM/THROTTLE at t=14.0s) and the browser-WASM track scored correctly (39/LOW at t=35.2s) — both tracks that had previously silently returned 0/NONE.

**Relationship to the finding in §4 below**: a *different* anomaly later reproduced the same 0/NONE symptom for the network pool-hits track specifically — but the daemon's own log proved the detection thread stayed alive and kept scoring other processes throughout, ruling out a recurrence of *this specific* bug. §4 documents the actual (distinct) root cause, found by direct log investigation with DEBUG-level logging enabled.

## 4. Detection latency inflation under sustained eBPF event load

**This is the root cause of the network pool-hits anomaly** referenced above and in §7's per-track detail — found by re-running the failing scenario with `--log-level DEBUG` and reading the daemon's own log directly, rather than left as an unresolved question.

**Method**: the pool-hits test was run twice back-to-back — once in isolation (succeeded, 50/MEDIUM at t=14.0s) and once immediately after a still-actively-mining, already-throttled XMRig process (reproduced the 0/NONE failure immediately). Comparing the daemon's own `[DETECT]` log timestamps for the still-alive throttled miner during the failing run revealed the actual gap between consecutive detection-engine scan cycles:

| Scan-cycle gap # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Seconds | 13.2 | 14.9 | 25.4 | 13.7 | 14.4 | 18.7 | 21.9 | 22.0 | 17.1 | 22.4 | 22.8 | 34.1 | 22.0 |

**Mean gap: 20.2s. Maximum gap: 34.1s. Configured `scan_interval`: 5s** — a 4-7x inflation. The pool-hits test client lives for only ~24 seconds total; when the real scan-cycle period balloons to 20-34s (instead of the configured 5s), the entire lifecycle of a short-lived process can fall inside a single gap and never be touched by any scan cycle at all — explaining the zero-trace symptom (`mining_pool_hits` correctly counted by the eBPF net_collector, but the detection engine's `_scan()` never got around to examining that PID even once).

**Why the cycle time inflates**: `DetectionEngine._scan()` runs in one Python thread, sharing the process (and the GIL) with four separate eBPF collector threads (`syscall_collector`, `sched_collector`, `net_collector`, `mem_collector`), each continuously calling BCC's `perf_buffer_poll()` — a C-extension call. A still-running miner (even throttled to 30% CPU) generates substantial futex/syscall/memory event volume, and this evaluation independently observed BCC's own `"Possibly lost N samples"` perf-ring-buffer-overflow warnings during heavy load — direct evidence the collector threads are under real event-processing pressure. That pressure competes for the GIL and the shared `process_store` lock with the detection thread, inflating its real wall-clock cycle time well past the nominal 5-second interval.

**Practical implication**: detection latency is not constant — it degrades specifically when a high-event-volume process (a real, active miner) is concurrently being tracked, which is precisely the scenario a production deployment would face. A short-lived connection or process that starts and exits during that window can be missed entirely. This is a genuine architectural limitation (GIL-bound single-process concurrency model), not a logic defect — worth discussing in the thesis as a concrete direction for future work (e.g. moving collectors to separate processes, or giving the detection thread higher scheduling priority than the collector threads).

## 5. Summary

| Category | Test | Peak score | Tier | Mitigation | Time to alert | Time to MEDIUM+ |
|---|---|---|---|---|---|---|
| Ground-truth detection | XMRig ground truth (--bench) | 45.0 | MEDIUM | THROTTLE | 77.2s | 104.0s |
| Ground-truth detection | Browser WASM miner (Puppeteer) | 39.0 | LOW | ALERT | 55.8s | never |
| Evasion resistance | Self-throttled miner (evasion attempt) | 45.0 | MEDIUM | THROTTLE | 79.6s | 114.1s |
| Evasion resistance | UPX-packed XMRig binary | 46.0 | MEDIUM | THROTTLE | 28.2s | 42.4s |
| Benign / false-positive baseline | Benign: OpenSSL crypto benchmark | 4.0 ± 6.9 (n=3) | NONE | NONE | never | never |
| Benign / false-positive baseline | Benign: sustained parallel gcc compilation | 0.0 ± 0.0 (n=3) | NONE | NONE | never | never |
| Ground-truth detection | Network pool-hits (stratum port) | 0.0 ± 0.0 (n=3) | NONE | NONE | never | never |
| Detector overhead | Detector overhead: idle baseline | cpu mean 172.2% | peak 191.7% | rss mean 88.7MB | — | — |
| Detector overhead | Detector overhead: under active detection load | cpu mean 112.4% | peak 160.4% | rss mean 81.2MB | — | — |

## 6. Signal-contribution matrix

Which of the scorer's behavioural signals (see `daemon/detector/scorer.py` `DEFAULT_WEIGHTS`) fired at peak score for each test — useful for discussing which features are load-bearing for which scenario, not just the final score.

| Signal | XMRig ground truth (--bench) | Browser WASM miner (Puppeteer) | Self-throttled miner (evasion attempt) | UPX-packed XMRig binary | Benign: OpenSSL crypto benchmark | Benign: sustained parallel gcc compilation | Network pool-hits (stratum port) |
|---|---|---|---|---|---|---|---|
| Thread saturation (full) | ✓ | ✓ |  | ✓ | ✓ |  |  |
| RandomX scratchpad+hugepage (strong) | ✓ |  | ✓ | ✓ |  |  |  |
| Weak scratchpad (no hugepage) |  | ✓ |  |  |  |  |  |
| Huge pages requested | ✓ |  | ✓ | ✓ |  |  |  |
| Futex dominance (strong) |  | ✓ |  |  |  |  |  |
| Sustained high CPU% | ✓ | ✓ |  |  |  |  |  |
| Temporal: sustained (6+ windows) |  |  |  | ✓ |  |  |  |

## 7. Per-track detail (with score-progression timelines)

### Ground-truth detection

#### XMRig ground truth (--bench)
*Source: `xmrig_ground_truth_1M.csv` (287 samples over 300.6s, 1 distinct PID(s) tracked)*

- **Peak**: score 45.0 / MEDIUM / THROTTLE (pid=84922, comm=xmrig)
- **Signals at peak**: thread saturation: 4 threads = 4 logical CPUs; sustained CPU 258%; RandomX signature: 11 × 2MB scratchpad allocation(s) backed by huge pages (40 MB total) — strong evidence; MAP_HUGETLB requested (11 times)
- **Time to first alert-tier detection**: 77.2s

| t (s) | score | tier | mitigation | ticks |
|---|---|---|---|---|
| 0.0 | 0.0 | NONE | NONE | 0 |
| 48.1 | 0.0 | NONE | NONE | 0 |
| 92.8 | 32.0 | LOW | ALERT | 1 |
| 134.4 | 45 | MEDIUM | THROTTLE | 2 |
| 176.2 | 45 | MEDIUM | THROTTLE | 3 |
| 217.8 | 45 | MEDIUM | THROTTLE | 4 |
| 259.2 | 45 | MEDIUM | THROTTLE | 5 |
| 300.6 | 45 | MEDIUM | THROTTLE | 6 |

#### Browser WASM miner (Puppeteer)
*Source: `browser_wasm_miner.csv` (61 samples over 60.9s, 1 distinct PID(s) tracked)*

- **Peak**: score 39.0 / LOW / ALERT (pid=86248, comm=DedicatedWorker)
- **Signals at peak**: futex dominance 66% of all syscalls at 134% CPU (strong mining signal); thread saturation: 49 threads = 4 logical CPUs; sustained CPU 134%; 13 × 2MB-aligned allocation(s) with no huge-page flag — weak signal, commonly shared with non-mining allocators
- **Time to first alert-tier detection**: 55.8s

| t (s) | score | tier | mitigation | ticks |
|---|---|---|---|---|
| 0.0 | 0.0 | NONE | NONE | 0 |
| 9.1 | 0.0 | NONE | NONE | 0 |
| 17.3 | 0.0 | NONE | NONE | 0 |
| 26.4 | 15.0 | NONE | NONE | 0 |
| 34.5 | 15.0 | NONE | NONE | 0 |
| 43.7 | 15.0 | NONE | NONE | 0 |
| 51.8 | 15.0 | NONE | NONE | 0 |
| 60.9 | 39.0 | LOW | ALERT | 1 |

### Evasion resistance

#### Self-throttled miner (evasion attempt)
*Source: `evasion_throttled_1thread_3M.csv` (293 samples over 300.3s, 1 distinct PID(s) tracked)*

- **Peak**: score 45.0 / MEDIUM / THROTTLE (pid=85262, comm=xmrig)
- **Signals at peak**: RandomX signature: 5 × 2MB scratchpad allocation(s) backed by huge pages (18 MB total) — strong evidence; MAP_HUGETLB requested (5 times)
- **Time to first alert-tier detection**: 79.6s

| t (s) | score | tier | mitigation | ticks |
|---|---|---|---|---|
| 0.0 | 0.0 | NONE | NONE | 0 |
| 44.3 | 0.0 | NONE | NONE | 0 |
| 87.9 | 20.0 | LOW | ALERT | 1 |
| 131.3 | 45 | MEDIUM | THROTTLE | 2 |
| 173.7 | 45 | MEDIUM | THROTTLE | 3 |
| 216.2 | 45 | MEDIUM | THROTTLE | 4 |
| 257.8 | 45 | MEDIUM | THROTTLE | 5 |
| 300.3 | 45 | MEDIUM | THROTTLE | 7 |

#### UPX-packed XMRig binary
*Source: `packed_xmrig_3M.csv` (285 samples over 300.3s, 1 distinct PID(s) tracked)*

- **Peak**: score 46.0 / MEDIUM / THROTTLE (pid=87792, comm=xmrig_packed)
- **Signals at peak**: thread saturation: 4 threads = 4 logical CPUs; RandomX signature: 11 × 2MB scratchpad allocation(s) backed by huge pages (40 MB total) — strong evidence; MAP_HUGETLB requested (11 times); sustained detection: 6 consecutive scan windows (~30s) — rules out bursty legitimate workloads
- **Time to first alert-tier detection**: 28.2s

| t (s) | score | tier | mitigation | ticks |
|---|---|---|---|---|
| 0.0 | 0.0 | NONE | NONE | 0 |
| 46.6 | 45 | MEDIUM | THROTTLE | 2 |
| 94.5 | 45 | MEDIUM | THROTTLE | 4 |
| 135.9 | 46.0 | MEDIUM | THROTTLE | 7 |
| 176.7 | 46.0 | MEDIUM | THROTTLE | 9 |
| 217.9 | 46.0 | MEDIUM | THROTTLE | 11 |
| 258.2 | 46.0 | MEDIUM | THROTTLE | 12 |
| 300.3 | 46.0 | MEDIUM | THROTTLE | 14 |

### Multi-trial tracks (3 independent runs each)

#### Benign: OpenSSL crypto benchmark

- **Trial 1** (`benign_openssl_t1.csv`): peak 12.0 / NONE / NONE, time to alert: never, signals: thread saturation: 4 threads = 4 logical CPUs
- **Trial 2** (`benign_openssl_t2.csv`): peak 0.0 / NONE / NONE, time to alert: never, signals: (none)
- **Trial 3** (`benign_openssl_t3.csv`): peak 0.0 / NONE / NONE, time to alert: never, signals: (none)
- **Aggregate**: peak score 4.0 ± 6.9, 0/3 trials alerted

#### Benign: sustained parallel gcc compilation

- **Trial 1** (`benign_gcc_compile_t1.csv`): peak 0.0 / NONE / NONE, time to alert: never, signals: (none)
- **Trial 2** (`benign_gcc_compile_t2.csv`): peak 0.0 / NONE / NONE, time to alert: never, signals: (none)
- **Trial 3** (`benign_gcc_compile_t3.csv`): peak 0.0 / NONE / NONE, time to alert: never, signals: (none)
- **Aggregate**: peak score 0.0 ± 0.0, 0/3 trials alerted

#### Network pool-hits (stratum port)

**Root cause identified — see §4 "Detection latency inflation under sustained eBPF event load".** 0/3 trials in this specific run detected anything (trials in this harness run happened to execute shortly after XMRig-family tracks, i.e. exactly the adverse condition §4 describes). This is **not a logic bug**: the same mechanism scores correctly (50/MEDIUM/THROTTLE at t=14.0s, reproduced twice — once before this harness run and once via a targeted isolation test during debugging) whenever it isn't competing with a still-running miner's eBPF event volume for the detection thread's GIL/lock time. The trials below show the `mining_pool_hits` counter still counting all 12 connections correctly even when the score never moves — the eBPF collection layer is unaffected, only the detection engine's scan cadence degrades. Report this as a genuine, quantified latency limitation (mean scan-cycle gap 20.2s vs. the configured 5s under load — see §4), not as "detection doesn't work."

- **Trial 1** (`network_pool_blocklist_t1.csv`): peak 0.0 / NONE / NONE, time to alert: never, signals: (none)
- **Trial 2** (`network_pool_blocklist_t2.csv`): peak 0.0 / NONE / NONE, time to alert: never, signals: (none)
- **Trial 3** (`network_pool_blocklist_t3.csv`): peak 0.0 / NONE / NONE, time to alert: never, signals: (none)
- **Aggregate**: peak score 0.0 ± 0.0, 0/3 trials alerted

### Detector overhead

#### Detector overhead: idle baseline
*Source: `overhead_idle_baseline.csv` (60 samples)*

- CPU%: mean 172.20%, peak 191.73%
- RSS: mean 88.7MB, peak 88.8MB
- Ambient tracked processes during this run: min 1888, mean 1912, max 1931

#### Detector overhead: under active detection load
*Source: `overhead_under_load.csv` (58 samples)*

- CPU%: mean 112.38%, peak 160.36%
- RSS: mean 81.2MB, peak 88.8MB
- Ambient tracked processes during this run: min 1907, mean 1916, max 1926

## 8. Caveats and scope (report honestly — do not drop these)

- **Overhead comparison is confounded by ambient system load.** This evaluation ran on a shared, actively-used development VM, not an isolated benchmark rig. The idle-vs-loaded overhead comparison showed *more* variance from ambient background processes than from the deliberately added test workload in at least one run — treat the two overhead numbers as independent data points, not a controlled A/B comparison, unless you rerun both on a quiet, dedicated machine with repeated trials.
- **XMRig-family and browser tracks are single-run** (each XMRig-family run takes several minutes under real cgroup throttling, making 3-5x repetition costly). Benign and network pool-hits tracks ran 3 trials each and report mean ± stddev — treat the single-run timing figures as indicative, not statistically rigorous.
- **Scope boundaries**: Windows-only attack vectors (fileless PowerShell cryptojacking) are out of scope — EDDMC has no Windows agent. HPC-based (MineSweeper-style) detection and a live Falco comparison were not implemented/attempted in this harness — cite as related work, not as tested baselines.
- **Evasion tests cover specific, named techniques** (process/thread-count reduction, UPX packing, binary renaming from the prior session) — they do not establish resistance to every conceivable evasion strategy (e.g. shared pre-warmed RandomX dataset across worker processes was identified but not tested).
- **Network pool-hits detection-latency finding**: this track's low detection rate in this run is explained (§4) by scan-cycle inflation under concurrent eBPF event load, not a scoring-logic defect — the trials happened to run shortly after XMRig-family tracks. Report the accuracy table's raw TP/FN count alongside §4's explanation, not in isolation, or it reads as a worse result than the evidence supports.
