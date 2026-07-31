# Baseline comparison notes (Chapter 6, Part B)

## Outcome: stopped at B0 — `on_cpu_ns` is not a usable CPU signal, and no substitute was used

Per this task's own explicit instruction ("If `on_cpu_ns` is also unusable, say so and stop;
the comparison cannot be made honestly without a CPU signal available from t=0"), Part B
(B1–B4: baseline detectors, parameter sweep, comparison table, figure) was **not attempted**.
This is not a shortcut — it follows directly from what B0's validation found, detailed below.
No workaround, substitute signal, or new capture was used to route around this, since Part B
is scoped to offline replay only and the ground rules forbid inventing a value.

## B0: what was checked and what it found

The proposed formula (`cpu_fraction = delta(on_cpu_ns) / (delta(wall_clock_ns) * n_cores)`)
was implemented and run against `on_cpu_ns` from the existing capture CSVs, using a rolling
window as specified. Before sweeping any parameter, it was validated against tracks with a
known-expected CPU profile — this surfaced the problem immediately, on the very tracks the
comparison needs to work on:

| Track | pid (most-sampled) | Window checked | Δ wall-clock | Δ `on_cpu_ns` | Implied CPU% | Expected |
|---|---|---|---|---|---|---|
| `xmrig_ground_truth_1M.csv` (4-thread, full saturation) | 84922-class (comm=xmrig) | full 295s | 295s | 35.9ms | ~0.01% | ~400% (4 cores fully busy) |
| `evasion_throttled_1thread_3M.csv` (confirmed 1 thread throughout) | comm=xmrig | full 293s | 293s | 29.5ms | ~0.01% | ~90-100% (1 core saturated) |
| `packed_xmrig_3M.csv` | comm=xmrig_packed | full 300s | 300.3s | 21ms | 0.01% | ~400% |
| `browser_wasm_miner.csv` | comm=DedicatedWorker | full 61s | 60.9s | 37ms | 0.06% | substantial (active WASM hashing) |
| `benign_gcc_compile_t1.csv` (a single `cc1` pid) | 83319 | 3.0s→30.4s | 27.4s | **-378ms (negative)** | **-1.38%** | ~100% while compiling, then process exit |
| `benign_openssl_t1.csv`, worker pids (`-multi 4` children, not the parent) | 83121/83122/83123 | ~30s each | ~30s | ~21s / ~16.3s / ~16.1s | ~70% | ~70-100% (matches expectation) |

Every mining track — the exact workloads this comparison exists to test — reads as
essentially 0% CPU regardless of confirmed full saturation. The gcc worker shows an
*impossible negative delta* (a monotonic counter cannot decrease). Only the openssl child
processes behave as expected.

## Root cause (traced to source, not guessed)

`daemon/ebpf/sched_monitor.c` accumulates `on_cpu_ns` in a BPF hash map keyed by **raw TID**,
not by process (TGID) — confirmed both by the tracepoint code (`args->prev_pid`/`next_pid`,
which are kernel per-thread ids) and by the collector's own code comment
(`sched_collector.py`/`sched_monitor.c`: *"sched_stats is keyed by raw TID here... one entry
per thread"*). On thread/process exit, that TID's entry is **deleted immediately**
(`sched_stats.delete(&tid)`), a deliberate choice documented in the source to stop BCC's
fixed-size hash map from filling permanently under normal thread churn.

This has two consequences, both reproduced above:

1. **Long-lived multi-threaded processes** (every XMRig variant here, in both 1-thread and
   4-thread configurations): the "process" as tracked in the CSV is really just its
   comm-labelled leader/main thread. If that thread mostly coordinates while separate worker
   threads do the RandomX hashing, the leader's own `on_cpu_ns` reflects only its own
   near-idle time — the workers' CPU time is accumulated under different TIDs that are
   deleted from the map (and never aggregated into the tracked process's entry) as soon as
   those threads exit or are recycled. This is consistent with the ~0.01% readings on all
   four mining/near-miner tracks, including the nominally single-threaded evasion track,
   which evidently still delegates the actual hash loop to a thread distinct from its leader.
2. **Very short-lived processes** (individual `cc1`/`as`/`ld` invocations spawned by a
   parallel `-j4` build): under rapid process creation, the kernel recycles PIDs faster than
   the daemon's own scan cadence (already documented as slow — `REPORT.md` §4). A tracked
   "pid" in the store can silently become a *different*, unrelated short-lived process
   between one scan and the next, since the dead-pid check (`os.path.exists(f"/proc/{pid}")`)
   only confirms *some* process now holds that number, not that it's the same one. This
   explains the frozen-then-reset, occasionally negative deltas seen on the gcc track.

The openssl worker children are the exception that proves the rule: they are single,
long-lived OS threads that do their own work directly (no internal delegation to short-lived
helper threads), so TID == the tracked PID for their entire life and the counter behaves
correctly.

## Why no substitute signal was used

The scorer's existing `cpu_bound_ratio` (involuntary-switch fraction) is captured reliably in
these same CSVs and was used throughout Tasks 1 and 6 without any of the above anomalies, but
it measures a materially different thing — "does this process get pre-empted while still
runnable" is a proxy for compute-boundedness, not a CPU-time percentage, and B1's design
(`T` swept across {60,70,80,85,90,95} *percent*) specifically calls for a genuine utilisation
percentage. Substituting a differently-defined signal would not be "deriving CPU utilisation
from `on_cpu_ns`" as asked, and risks quietly changing what the baseline detector actually
measures without saying so — the ground rule against inventing a value applies here to
inventing a stand-in methodology, not just a stand-in number. Per the instruction, this is
reported as a stop, not routed around.

## What would unblock this

Fixing `sched_collector.py` to aggregate `on_cpu_ns` across all TIDs sharing a TGID before a
thread's entry is deleted (summing into a persistent per-TGID counter rather than only
decrementing `thread_count`) would make the signal usable — but that is a collector code
change requiring a new capture to verify, which is out of scope for an offline-replay-only
round. Flagging this as a concrete, scoped follow-up rather than leaving it as a vague "future
work" line: the fix is localized to the exit-tracepoint handler in
`daemon/ebpf/sched_monitor.c` and the corresponding read path in
`daemon/collector/sched_collector.py`.

## Files produced this round

- `reports/INTEGRITY_CHECK.md` (Part A)
- `reports/BASELINE_COMPARISON_NOTES.md` (this file, Part B)

No `evaluation/baseline_detectors.py`, `evaluation/results/baseline_sweep.csv`,
`evaluation/results/baseline_comparison.md`, or `evaluation/figures/fig_baseline_comparison.png`
were produced, as a direct consequence of B0's outcome above.
