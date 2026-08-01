# Postfix verification: TID-attribution fix in sched_monitor.c (2026-08-01)

**Pre-fix baseline SHA**: `3848e8c648a9ba761f6a4d28a441d0e128114ba3` (committed).
**Post-fix state**: uncommitted at time of writing — `daemon/collector/sched_collector.py`
and `daemon/ebpf/sched_monitor.c` modified; committing was not requested this round, so the
change is left staged for review rather than committed unilaterally.

## Direct answer

**Yes. Peak score rose from 45.0 to 52.0 on the same track configuration. Tier stayed
MEDIUM (both under the 60-point HIGH boundary), but the mechanism changed materially: the
weighted signals alone now reach 52 — above the 45-point hard-evidence floor that was
previously the ONLY thing carrying detection (the pre-fix raw weighted sum was 38, below
the floor). Detection also got much faster: time to MEDIUM dropped from 104.0s to 22.2s,
and the process never passed through a distinctly observable LOW tick post-fix — it jumped
straight from NONE to MEDIUM in one scan cycle.**

---

## Step 1 — extent of the defect (before any fix)

Read `daemon/ebpf/sched_monitor.c` and `daemon/collector/sched_collector.py` (the prompt's
`daemon/collectors/` path does not exist — the directory is singular, `daemon/collector/`).

- **`on_cpu_ns`**: confirmed affected (this was the entry point from
  `reports/BASELINE_COMPARISON_NOTES.md`).
- **`voluntary_switches` / `involuntary_switches`**: **also affected, confirmed by direct
  source read** — all three fields live in the same `struct sched_stats`, updated in the
  same code block (`sched_switch`'s "account CPU time for the task being switched out"),
  looked up via the same raw-TID key, and discarded together (no aggregation) when
  `sched_process_exit` deleted a non-leader thread's entry. This directly explains why
  `cpu_bound_ratio` (`involuntary / (involuntary + voluntary)`) read near-zero
  (0.03–0.06) at every mining-track peak tick checked, despite the independently-measured
  `cpu_percent` signal showing genuine saturation (e.g. 258% at the pre-fix peak) — the
  process's real preemption activity was happening on worker threads whose switch counts
  were never attributed to the tracked leader entry.
- **`futex` counts**: **not affected** — `daemon/ebpf/syscall_monitor.c` already keys
  `syscall_stats` by TGID (`bpf_get_current_pid_tgid() >> 32`, confirmed both by the code
  and its own comment: *"syscall_stats is keyed by TGID... only clean up on the
  thread-group leader's exit"*). Checked directly against the pre-fix peak tick:
  `futex_ratio` was genuinely 3.1% of all syscalls — far below even the moderate (20%)
  threshold. This reflects real workload behaviour (RandomX worker threads spend their
  time hashing, not synchronising), not a collection defect.
- **Deletion timing**: `sched_process_exit` deleted a non-leader thread's map entry
  immediately, with no aggregation to the leader beforehand — the root cause.
  `mem_monitor.c` / `net_monitor.c` were not examined (out of this step's stated scope).

**Which of the 14 weighted signals (`docs/ARTEFACT_INVENTORY.md`) could not have fired
correctly for a multi-threaded process, pre-fix:**

| Signal | Affected? | Why |
|---|---|---|
| `cpu_bound_strong` (≥0.92) | **Yes** | derives from involuntary/voluntary switches, both TID-keyed and lost on worker exit |
| `cpu_bound_moderate` (≥0.75) | **Yes** | same |
| `futex_strong` / `futex_moderate` | No | syscall_monitor.c already TGID-keyed |
| `compute_pure` | No | same (read/write counters, TGID-keyed) |
| `thread_full_sat` / `thread_partial_sat` | No | thread_count already uses the TGID-based fork/exit path, protected from the raw-TID entries |
| `cpu_high` (≥85%) | No — but see caveat | `cpu_percent` comes from `psutil`, not this eBPF map at all; it has its own separate, already-documented scan-cadence limitation (Task 7), unrelated to today's fix |
| `scratchpad_exact` / `scratchpad_weak` / `huge_pages` | Not checked | `mem_monitor.c`, out of this step's scope |
| `pool_connection` | Not checked | `net_monitor.c`, out of this step's scope |
| `sustained_medium` / `sustained_high` | Indirectly | these depend on `suspicious_ticks`, which accumulates only on ticks where the *total* score crosses a threshold — if `cpu_bound_*` was structurally suppressed, some ticks that should have crossed the threshold didn't, so temporal accumulation could be slower too, compounding rather than independently broken |

**Net: at minimum 2 of the 14 signals (`cpu_bound_strong`, `cpu_bound_moderate`) could not
fire correctly for any multi-threaded process, plus an indirect knock-on effect on the two
temporal signals.**

## Step 2 — the fix

Two changes, attribution-only (no scoring/weight/threshold/floor logic touched):

1. **`daemon/ebpf/sched_monitor.c`**: added a `tgid` field to `struct sched_stats`,
   populated at fork time (`sched_process_fork`, which runs in the *calling* thread's own
   context, so `bpf_get_current_pid_tgid() >> 32` reliably gives the shared group tgid
   regardless of which thread in the group called `clone()`). Also folds an exiting
   non-leader thread's `on_cpu_ns`/`voluntary_switches`/`involuntary_switches` into the
   leader's entry before deleting it — a defensive backstop for threads that exit between
   polls, not the primary fix (see below).
2. **`daemon/collector/sched_collector.py`**: `_poll_bpf_maps()` now groups every live
   `sched_stats` entry by its `tgid` field (falling back to its own key if `tgid==0`, i.e.
   unknown/pre-existing-at-load) and sums `on_cpu_ns`/switch counts across the whole group
   on **every poll**, writing only the aggregated total to the group leader's
   `process_store` entry.

**Why both were needed — a real mid-course correction.** The first fix attempt was
exit-time aggregation only (in `sched_monitor.c`). Telemetry verification (Step 3, first
attempt) showed it made *no difference at all* during a live 30s capture: `derived_pct`
stayed at ~0.001–0.01%, identical to pre-fix. Root cause: XMRig's worker threads don't
exit until the whole process does, so an exit-time-only fix never fires during the entire
live monitoring window — the exact window detection needs to work in. This is reported
plainly because it's a real finding: **a fix that only helps once threads exit is
functionally useless for live/real-time scoring of a long-running process.** The second
(current) fix adds live, continuous userspace aggregation, verified below to actually work.

**Performance note (eBPF vs. userspace aggregation)**: continuous aggregation was
implemented in userspace, not by adding a second live-updating BPF map keyed by tgid.
`sched_switch` fires on every context switch system-wide — a very hot path — so adding an
extra hash lookup+update there on every event would add measurable overhead system-wide.
Grouping in `_poll_bpf_maps()` instead costs one O(n) pass (n = live thread entries, bounded
by `MAX_PIDS`=4096) **once per poll interval**, which — per the already-documented
scan-cadence defect (`REPORT.md` §4) — happens far less often than raw `sched_switch`
events. This was the lower-overhead and more reviewable choice.

**Counter resets / PID reuse**: the live scorer (`scorer.py`/`fingerprint.py`) reads
`cpu_bound_ratio` as an instantaneous ratio at scoring time, never as a delta across polls
— so the negative-delta hazard found on the gcc worker in Part B does not affect the live
detection path at all, before or after this fix. It only matters for offline analysis code
that computes deltas across polls (this task's own `verify_sched_fix.py`, and any future
baseline detector). `verify_sched_fix.py` guards this explicitly: a computed delta below
zero is flagged and excluded from the derived-percentage calculation rather than reported
as a negative rate. No collector-level PID-generation tracking was added — out of scope for
"minimal and reviewable," and not exercised by this task's single long-lived XMRig track.

## Step 3 — telemetry verification (before any scoring run)

`evaluation/verify_sched_fix.py`, `evaluation/results/postfix/sched_fix_telemetry.csv`.
30s of real XMRig (`--bench=1M --randomx-mode=light -t 4` — light mode substituted for the
environment's limited free memory; still exercises 4 real worker threads, which is what
this fix targets), sampled every 1s against an independent `psutil` reading of the same
process.

| Check | Result |
|---|---|
| `on_cpu_ns` monotonic, no negative deltas | **Pass** — `any_negative_delta=False` across all 30 polls |
| Derived CPU% (`on_cpu_ns` delta / 1s) approximates independent `psutil` reading | **Pass** — derived ranged ~234–355%, psutil (independent) ranged ~262–330%, same ballpark throughout a 30s run (first fix attempt: derived was ~0.001–0.01% against psutil's ~270–330% — no correlation at all) |
| Switch counts non-zero and plausible for a saturated process | **Pass** — `involuntary_switches` climbed from 767 to 20,091 over 30s while `voluntary_switches` stayed at 10–15 — a saturated, rarely-yielding process, the textbook CPU-bound pattern. Pre-fix this was inverted (`voluntary` climbing, `involuntary` frozen at 9) |

All three pass. Proceeded to Step 4.

## Step 4 — single-track scoring comparison

Clean daemon confirmed before capture: single instance, `systemctl is-active eddmc` →
`inactive`, no stale process-store state (fresh restart), no orphaned miner from a previous
run (`ps aux` checked clean). `dry_run: false` via the same scoped `--config` override used
for the original Task 7 measurement (`local.yaml` untouched).

Capture: `--bench=1M --randomx-mode=light -t 4`, light mode substituted for
`xmrig_ground_truth_1M.csv`'s likely fast/dataset-mode default — this test host has
repeatedly hit memory pressure this session (as low as ~470MB free during this same run),
and fast mode's ~2GB RandomX dataset was judged too risky to attempt. 4 threads were kept
to preserve the multi-threaded aspect the fix targets. 300 rows written to
`evaluation/results/postfix/xmrig_postfix.csv`.

| | Pre-fix (recorded) | Post-fix (this run) |
|---|---|---|
| Peak score | 45.0 | **52.0** |
| Peak tier | MEDIUM | MEDIUM |
| Time to LOW | 77.2s | **never observed — skipped straight from NONE to MEDIUM in one scan** (t=21.2s NONE/0.0 → t=22.2s MEDIUM/44.0) |
| Time to MEDIUM | 104.0s | **22.2s** |
| Time to HIGH | never | never |
| Time to CRITICAL | never | never |
| Mitigation applied | THROTTLE | THROTTLE |

**Per-feature contribution breakdown** (`evaluation/build_postfix_comparison.py` →
`evaluation/results/postfix/feature_comparison.md`, same leave-one-out method as
`ablation_leave_one_out.md`, floor-inclusive deltas):

| Feature | Pre-fix contribution | Post-fix contribution | Newly nonzero? |
|---|---|---|---|
| thread saturation | 0.0 | 7.0 (raw weight 12, floor-clamped) | **YES** |
| RandomX scratchpad | 0.0 | 7.0 (raw weight 15, floor-clamped) | **YES** |
| huge pages requested | 0.0 | 5.0 | **YES** |
| scheduler CPU-boundedness | 0.0 | 6.0 (raw weight 6 — `cpu_bound_moderate` fired, exactly, no clamping) | **YES** |
| temporal sustained-detection | 0.0 | 7.0 (raw weight 14, floor-clamped) | **YES** |
| futex, compute-pure, pool connection | 0.0 | 0.0 | no |

The reported deltas above are **floor-clamped** (removing a feature can't drop the score
below the 45-point floor, so a delta can understate a feature's raw weight — the original
ablation report's own convention). The reasons text and raw weights resolve this precisely:
post-fix fired `thread_full_sat`(+12) + `scratchpad_exact`(+15) + `huge_pages`(+5) +
`cpu_bound_moderate`(+6, **new**) + `sustained_high`(+14, ticks=7≥6) = **52, exactly matching
the recorded score with no floor clamping needed** — the floor (45) is no longer doing any
work at this tick. Pre-fix, the same arithmetic (`thread_full_sat`+12, `cpu_high`+6,
`scratchpad_exact`+15, `huge_pages`+5, no temporal or cpu_bound signal) sums to 38, **below**
the 45 floor — confirming the floor was carrying 100% of detection pre-fix.

## Step 5 — the three consequences

1. **Does the weighted sum now reach HIGH (≥60) independently of the floor?** No, but it
   is no longer *dependent* on the floor either. Post-fix raw weighted sum = 52 (floor =
   45, so the floor is inactive here) — up from a pre-fix raw sum of 38 (below the floor,
   which is what carried detection to 45). **The ablation finding needs this exact
   qualification: `cpu_bound_moderate` (+6) and `sustained_high` (+14) were not
   "redundant" pre-fix — they were structurally unable to fire at all. Once fixed, they
   supply 20 of the 52 points, the majority of what's now above the floor.**
2. **Is CRITICAL (≥80) reachable?** Not through weighted signals alone at this
   configuration — gap is 80−52 = 28 points, and the largest remaining unfired signal
   without a live pool connection is `cpu_bound_strong` (+12, an upgrade from the
   already-firing +6 moderate tier, if the ratio crossed 92% instead of the observed 83%)
   plus `cpu_high` (+6, gated on `cpu_percent`, itself separately scan-cadence-limited) —
   at most +12 more, reaching ~64–70, still short of 80. **A live pool connection would
   close it easily**: `pool_connection`'s own weight is +40 (52+40=92, comfortably
   CRITICAL) — stated arithmetically as instructed, no mock stratum experiment run.
3. **Would the fingerprint confirmation gate (`daemon/fingerprint/assessor.py`) now be
   satisfiable?** The gate actually has five blocking conditions once its bundled
   `cond_features` check is unbundled into its three parts (the module's own docstring
   says "four," but the code's `if not (cond_sustained and cond_pool and cond_features)`
   evaluates five independent boolean facts): sustained CRITICAL ≥60s, a confirmed pool
   connection, `futex_ratio≥0.40`, `cpu_bound_ratio≥0.92`, `thread_cpu_ratio≥1.0`.
   Checked against the post-fix peak: only **thread_cpu_ratio** passes
   (`min(6/4, 2.0)=1.5≥1.0`). The other four fail: confidence never reached CRITICAL (the
   gate's own entry check short-circuits immediately on this), no pool connection,
   `futex_ratio`=3.1% (≪0.40), `cpu_bound_ratio`=0.83 (<0.92, close but under the *strong*
   threshold even though the *moderate* scorer threshold now fires). **Not satisfiable**
   with this observation — 1 of 5 conditions met.

## Step 6 — false-positive safety check

Replayed all 6 existing benign CSVs (`benign_openssl_t1/2/3.csv`,
`benign_gcc_compile_t1/2/3.csv`) through the identical, unchanged scorer via
`replay_scorer.py` — no recapture, no scoring-logic change. All 6 peaked at NONE or LOW
(12.0–24.0), well under the 40-point MEDIUM threshold; none reached LOW/MEDIUM *newly* as a
consequence of anything this fix changes.

**However, this replay is not fully meaningful for this specific fix.** Every one of these
CSVs' individual tracked PIDs is itself single-threaded (`thread_count=1` throughout, per
direct inspection) — the parallelism in `-multi 4`/`-j4` comes from multiple separate
*processes*, not from one multi-threaded process. Since today's fix only changes behaviour
for genuinely multi-threaded processes (TID≠TGID cases), it cannot have changed anything
for these specific historical rows either way — the replay confirms the *unaffected*
population stayed unaffected, which is necessary but not sufficient.

**Spot check** (labelled as such, not a re-evaluation): no readily-available openssl/gcc
invocation reliably produces genuine in-process multi-threading (rather than multi-process
parallelism) within this task's time budget, so a small **synthetic** substitute was used
instead — a plain 4-thread Python CPU-bound busy loop (pure arithmetic, no I/O, no memory
allocations resembling a RandomX scratchpad), captured live under the fixed daemon for 25s.
Confirmed the fix was genuinely exercised: `thread_count=5` (main + 4 workers), `on_cpu_ns`
climbed to ~20.9 billion ns over 20.4s wall-clock (substantial, correctly aggregated —
pre-fix this would have read near-zero), `involuntary`/`voluntary` switches both
substantial and roughly balanced (Python's GIL limits true parallelism, so this is not as
aggressively CPU-bound as a native miner, and correctly scored as such). **Result: peak
score 0.0/NONE for the entire capture — zero false positive.**
(`evaluation/results/postfix/benign_multithread_spotcheck.csv`.)

## Assessment: is a full re-evaluation justified?

**Not urgently, but it is now warranted as follow-up work, scoped narrowly.** This single
track shows the fix has a real, measurable, and correctly-directioned effect (peak score
+7, tier mechanism shifted from floor-dependent to weight-dominant, detection latency to
MEDIUM dropped from 104s to 22s) without introducing a false positive in the one benign
multi-threaded case tested. That is enough to justify: (a) re-running the other three
mining tracks (`evasion_throttled_1thread_3M.csv`'s config, `packed_xmrig_3M.csv`'s config)
under the fixed collector to see if the same +feature pattern holds, since this task's
scope was deliberately limited to one; and (b) a proper benign multi-threaded capture using
a real tool (not today's synthetic substitute) once one can be identified or purpose-built.
It does **not** currently justify recomputing the confusion matrix or ablation tables
wholesale — those still accurately describe the *old* collector's behaviour on data that
was captured under it, which is what they claim to be.

## Files produced this round

- `daemon/ebpf/sched_monitor.c` (modified — attribution fix)
- `daemon/collector/sched_collector.py` (modified — live per-poll aggregation)
- `evaluation/verify_sched_fix.py` (Step 3 telemetry check)
- `evaluation/build_postfix_comparison.py` (Step 4 feature-contribution comparison)
- `evaluation/results/postfix/sched_fix_telemetry.csv` (Step 3)
- `evaluation/results/postfix/xmrig_postfix.csv` (Step 4)
- `evaluation/results/postfix/feature_comparison.md` (Step 4)
- `evaluation/results/postfix/benign_multithread_spotcheck.csv` (Step 6)
- `reports/POSTFIX_VERIFICATION.md` (this file)

No file under `evaluation/results/` outside `evaluation/results/postfix/` was modified.
