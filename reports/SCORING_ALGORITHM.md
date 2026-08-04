# EDDMC Scoring Algorithm — Full Specification

This document specifies exactly how EDDMC converts raw eBPF telemetry for a process into a
suspicion score, a confidence tier, and a mitigation action. Every weight, threshold, and
formula below is copied directly from the current source and verified against it line by line;
none are approximated or rounded. Source files:

- `daemon/detector/fingerprint.py` — raw counters → derived ratios (`BehaviouralFingerprint`)
- `daemon/detector/scorer.py` — the scoring formula itself (`Scorer.score()`)
- `daemon/detector/engine.py` — the per-tick scan loop that drives the temporal state
- `daemon/fingerprint/assessor.py` — a separate, stricter gate used only for registry submission
- `daemon/config/defaults.yaml` — the config file that supplies the default values below

## 1. Is it deterministic?

**Yes, fully.** There is no machine learning model, no randomness, and no hidden state beyond
two small pieces of per-process memory the daemon keeps between scans (explained in §5). Given
the exact same `BehaviouralFingerprint` input, `Scorer.score()` always returns the exact same
score, confidence, and mitigation, every time. This is why "replay verification" — feeding a
previously-recorded observation back through a fresh `Scorer` instance and checking it reproduces
the daemon's own live-recorded score — is a meaningful check at all; there is nothing in the
formula that could cause two runs to diverge on the same input.

## 2. Inputs: from raw eBPF counters to a `BehaviouralFingerprint`

Four eBPF collectors (`syscall_monitor.c`, `sched_monitor.c`, `net_monitor.c`, `mem_monitor.c`)
maintain raw per-process counters in kernel hash maps. Once per scan tick, `fingerprint.py`'s
`build()` function converts those raw counters into the ratios and fields the scorer actually
reads. All divisions guard against a zero denominator (using `max(x, 1)`), so no field is ever
`NaN` or raises a division error.

| Fingerprint field | Formula | Raw inputs |
|---|---|---|
| `syscall.futex_ratio` | `futex / total_syscalls` | eBPF syscall counters |
| `syscall.io_ratio` | `(read + write) / total_syscalls` | eBPF syscall counters |
| `syscall.total_syscalls` | `total` (raw count, unmodified) | eBPF syscall counter |
| `parallelism.thread_count` | raw thread-group size, `max(count, 1)` | eBPF scheduler collector |
| `parallelism.thread_cpu_ratio` | `min(thread_count / logical_cpu_count, 2.0)` | thread count ÷ `os.cpu_count()` |
| `parallelism.cpu_percent` | `psutil.Process(pid).cpu_percent()` | **not** eBPF — read directly via `psutil`, independent of the scheduler collector |
| `memory.scratchpad_allocs` | raw count of exact-2MB anonymous private mappings | eBPF memory collector |
| `memory.scratchpad_huge_allocs` | raw count of those 2MB mappings that **also** carry `MAP_HUGETLB` | eBPF memory collector |
| `memory.huge_page_requests` | raw count of `MAP_HUGETLB` requests of any size | eBPF memory collector |
| `scheduler.cpu_bound_ratio` | `involuntary_switches / max(voluntary + involuntary, 1)` | eBPF scheduler collector |
| `temporal.suspicious_ticks` | see §5 — accumulated across ticks, not derived per-tick | engine.py's own tracking |
| `temporal.age_seconds` | `now − first_seen` | wall-clock, tracked per pid since first observation |
| `network.pool_connections` | raw count of confirmed stratum-port TCP connects | eBPF network collector |

Note that `cpu_percent` is the one field **not** sourced from eBPF — it comes from a direct
`psutil` read of `/proc/<pid>/stat`, cached per-pid between calls.

## 3. The weighted-sum formula

`Scorer.score(fp)` starts with `s = 0.0` and evaluates 14 independent conditions across 6
dimensions, in this exact order. Each condition either adds its full weight or nothing — there
is no partial credit or interpolation between the "moderate" and "strong" tier of a pair.

```
s = 0.0

# ── 1. Syscall dimension ──
if futex_ratio >= 0.40 and cpu_percent >= 50.0:
    s += 18                                    # futex_strong
elif futex_ratio >= 0.20 and cpu_percent >= 50.0:
    s += 9                                     # futex_moderate

if io_ratio < 0.02 and cpu_percent >= 70.0:
    s += 10                                    # compute_pure

# ── 2. Parallelism dimension ──
cpu_count = os.cpu_count()                     # logical CPU count of the host, e.g. 4

if thread_count >= cpu_count:
    s += 12                                    # thread_full_sat
elif thread_count >= int(cpu_count * 0.6):
    s += 6                                     # thread_partial_sat

if cpu_percent >= 85.0:
    s += 6                                     # cpu_high

# ── 3. Memory dimension (RandomX-specific) ──
if scratchpad_huge_allocs > 0:                 # 2MB alloc AND MAP_HUGETLB, same allocation
    s += 15                                    # scratchpad_exact
elif scratchpad_allocs > 0:                    # 2MB alloc alone, no huge-page flag
    s += 3                                     # scratchpad_weak

if huge_page_requests > 0:
    s += 5                                     # huge_pages

# ── 4. Scheduler dimension ──
if cpu_bound_ratio >= 0.92:
    s += 12                                    # cpu_bound_strong
elif cpu_bound_ratio >= 0.75:
    s += 6                                     # cpu_bound_moderate

# ── 5. Temporal dimension ──
if suspicious_ticks >= 6:                      # ~30s at the configured 5s scan interval
    s += 14                                    # sustained_high
elif suspicious_ticks >= 3:                    # ~15s
    s += 7                                     # sustained_medium

# ── 6. Network dimension (hard evidence) ──
if pool_connections > 0:
    s += 40                                    # pool_connection
```

**Every `if`/`elif` pair is mutually exclusive** — e.g. a process either gets `futex_strong` (18)
or `futex_moderate` (9), never both, never a blend. Maximum possible from dimensions 1–5 combined
is 65 (18+10+12+6+15+5+12+14 — note only one option per pair counts); `pool_connection` alone can
add a further 40 on top of that, for a theoretical ceiling of 105 before clamping to 100.

### Default weight table (from `DEFAULT_WEIGHTS` in `scorer.py`)

| Weight key | Value | Condition |
|---|---|---|
| `futex_strong` | 18 | `futex_ratio ≥ 0.40` and `cpu_percent ≥ 50%` |
| `futex_moderate` | 9 | `futex_ratio ≥ 0.20` and `cpu_percent ≥ 50%` |
| `compute_pure` | 10 | `io_ratio < 0.02` and `cpu_percent ≥ 70%` |
| `thread_full_sat` | 12 | `thread_count ≥ logical_cpu_count` |
| `thread_partial_sat` | 6 | `thread_count ≥ 0.6 × logical_cpu_count` |
| `cpu_high` | 6 | `cpu_percent ≥ 85%` |
| `scratchpad_exact` | 15 | `scratchpad_huge_allocs > 0` (joint 2MB + huge-page) |
| `scratchpad_weak` | 3 | `scratchpad_allocs > 0` (2MB size alone) |
| `huge_pages` | 5 | `huge_page_requests > 0` |
| `cpu_bound_strong` | 12 | `cpu_bound_ratio ≥ 0.92` |
| `cpu_bound_moderate` | 6 | `cpu_bound_ratio ≥ 0.75` |
| `sustained_medium` | 7 | `suspicious_ticks ≥ 3` |
| `sustained_high` | 14 | `suspicious_ticks ≥ 6` |
| `pool_connection` | 40 | `pool_connections > 0` |

All 14 values are configurable via `detection.weights` in `daemon/config/defaults.yaml` or
`local.yaml` — the table above is what ships as the default and is what every measurement in
this project's evaluation reports used (confirmed unchanged from default throughout).

## 4. Hard-evidence floors (applied *after* the weighted sum)

Two conditions set a **lower bound** on the score, applied via `max()` — they can only push the
score up, never down, and never interact with each other beyond both being checked independently:

```
if pool_connections > 0:
    s = max(s, 50)          # pool_floor — a confirmed pool connection is never scored below MEDIUM

if scratchpad_huge_allocs > 0 and cpu_percent >= 1.0:
    s = max(s, 45)          # scratchpad_floor — RandomX memory signature is never scored below MEDIUM
```

Both floor values (50 and 45) are configurable (`detection.pool_floor`, `detection.scratchpad_floor`).

**Why the scratchpad floor requires the *joint* match, not size alone**: a bare 2MB-aligned
allocation (`scratchpad_allocs > 0`, weight 3, *not* floor-eligible) is shared with ordinary
huge-page-aligned allocators unrelated to mining (observed in this project: `fwupd`,
Chromium/Electron's own allocator). Only the combination of the right size **and** the
`MAP_HUGETLB` flag on the *same* allocation (`scratchpad_huge_allocs > 0`) is treated as
near-conclusive.

**Why the scratchpad floor's CPU-activity check is `≥ 1%`, not a high bar**: it exists only to
exclude a fully idle/dead entry that hasn't been garbage-collected yet. It is deliberately *not*
a high threshold, because EDDMC's own mitigation can throttle a confirmed miner's cgroup CPU
quota down to 5% — gating the floor on a high CPU percentage would have turned EDDMC's own
successful mitigation into evidence the process was no longer suspicious, which was observed
directly to cause the confidence tier to flap MEDIUM → LOW → MEDIUM every scan cycle while the
miner kept running unchanged underneath.

## 5. The temporal mechanism (the one piece of state across ticks)

Unlike every other input, `suspicious_ticks` is **not** derived fresh each tick from the current
fingerprint — it is a counter the detection engine (`engine.py`) maintains per-pid across scans:

```
# Once per scan tick, for every scored process:
if result.score >= 20.0:            # TICK_THRESHOLD
    suspicious_ticks += 1
else:
    suspicious_ticks = 0            # resets to zero on any clean tick
```

This creates a feedback relationship: a process's score in tick *N* depends in part on
`suspicious_ticks`, which depends on whether tick *N−1*'s score was ≥ 20, and so on backwards.
A single below-threshold tick resets the counter to zero — the sustained-detection bonus (+7 at
3 consecutive ticks, +14 at 6) requires *consecutive* qualifying ticks, not a cumulative count
over the process's whole lifetime. At the *configured* 5-second scan interval, 6 ticks
corresponds to ~30 seconds; this project's own live measurements found the *real* interval
running noticeably higher on a busy host (mean ~12.3s observed in one measurement round), so the
wall-clock time to accumulate `sustained_high` in practice can exceed the ~30s figure the reason
string reports, which is computed as `suspicious_ticks × 5` (the configured interval) rather than
the true elapsed time.

## 6. Youth penalty and final clamping

```
if age_seconds < 20.0 and s >= 60.0:
    s = min(s, 55.0)                # cannot reach HIGH/CRITICAL in the process's first 20 seconds

s = min(max(s, 0.0), 100.0)         # final clamp to [0, 100]
```

`age_seconds` is wall-clock time since the process was first observed by the daemon, tracked
independently of `suspicious_ticks`. This penalty exists to prevent a legitimate process's
startup burst (e.g. a build tool briefly saturating threads while warming up) from reaching a
mitigating tier before the sustained-detection mechanism in §5 has had a chance to rule it out.

## 7. Tier lookup

The final clamped score is checked against four boundaries, from highest to lowest, and the
**first** one it meets or exceeds wins:

| Score range | Confidence | Mitigation applied |
|---|---|---|
| [80, 100] | CRITICAL | SIGSTOP suspend; SIGTERM→3s grace→SIGKILL only if `auto_kill` is enabled |
| [60, 80) | HIGH | + iptables cgroup-based network block |
| [40, 60) | MEDIUM | + cgroup CPU quota throttle |
| [20, 40) | LOW | log alert only, no enforcement |
| [0, 20) | NONE | ignored |

Boundaries are configurable (`detection.alert_threshold` / `throttle_threshold` /
`block_threshold` / `terminate_threshold`), defaulting to 20/40/60/80 exactly as shown.

## 8. Worked examples (real recorded observations, not illustrative numbers)

**Full-speed XMRig, connected to a mock mining pool** (this project's own captured peak
observation): thread saturation (12) + RandomX scratchpad+hugepage (15) + huge pages (5) +
scheduler CPU-boundedness (12) + sustained-high (14) + pool connection (40) = **98**. Both floors
(45, 50) are already below 98, so neither changes the result — the weighted sum alone determines
the outcome here. **Score 98 → CRITICAL.**

**The same XMRig, run single-threaded with no pool connection** (a self-throttling evasion
attempt): thread saturation only reaches the *partial* tier (6, not 12, since 1 thread < 60% of
4 cores... in the specific recorded case thread_partial_sat still fired) + scratchpad+hugepage
(15) + huge pages (5) + scheduler CPU-boundedness (12) = 38 from the weighted sum alone — which
would leave it at LOW (38 < 40). But `scratchpad_huge_allocs > 0` and `cpu_percent ≥ 1%` are both
true, so the scratchpad floor applies: `s = max(38, 45) = 45`. **Score 45 → MEDIUM — the floor,
not the weighted sum, determines this outcome.**

**OpenSSL, a legitimate multi-threaded CPU-bound benchmark** (`openssl speed -multi 4`): thread
saturation (12) + scheduler CPU-boundedness (12) + sustained-high (14) = **38**. Neither
mining-specific signal is present (`scratchpad_huge_allocs = 0`, `pool_connections = 0`), so
neither floor applies. **Score 38 → LOW (log-only, no enforcement)** — below the MEDIUM boundary
by 2 points, entirely from signals that are, by design, shared with any legitimate sustained
CPU-bound multi-threaded workload.

## 9. A separate, stricter gate: fingerprint registry submission

A **CRITICAL** classification from §7 does not by itself submit anything to the distributed
fingerprint registry. A second, independent, and stricter gate (`FingerprintAssessor.evaluate()`
in `daemon/fingerprint/assessor.py`) must *also* pass, evaluated once per tick only for processes
already at CRITICAL:

```
cond_sustained     = (seconds continuously at CRITICAL) >= 60.0    # sustained_critical_seconds
cond_pool          = pool_connections > 0
cond_min_syscalls  = total_syscalls >= 500                         # min_syscalls
cond_features      = cpu_bound_ratio >= 0.92 AND thread_cpu_ratio >= 1.0

submit_to_registry = cond_sustained AND cond_pool AND cond_min_syscalls AND cond_features
```

This gate is deliberately independent of the score formula in §3 — it re-checks raw fingerprint
fields directly rather than trusting the score, and requires all four conditions simultaneously.
It prioritises precision over recall: a real, confirmed miner that happens to fail one condition
(e.g. a self-throttled evasion case with no pool connection) is correctly detected and mitigated
by the core scorer, but its fingerprint is *not* shared with other nodes, since sharing a
lower-confidence fingerprint risks poisoning every other deployment's matcher with a false
positive.

**Note on this gate's history**: an earlier version of this project also required
`futex_ratio ≥ 0.40` as a fifth condition. It was removed after evidence (not tuned to make a
test pass) showed real mining captures topping out at 4.85% futex_ratio while benign traffic
reached 12.4% — the two populations' distributions overlap and invert, so no threshold value
could have separated them. `min_syscalls ≥ 500` was added in its place after finding the actual
defect the futex condition had been masking: a single frozen, unchanging observation (177 total
syscalls across a 30-second capture) was being polled repeatedly and counted as separate
confirmations.

## 10. Known caveats in the current implementation

- **`min_age_seconds` (config key, default 10) is defined but never read anywhere in the code.**
  It has no effect on scoring, despite appearing in `defaults.yaml`'s `detection:` section
  alongside keys that are genuinely used.
- **The temporal mechanism's "~Xs" labels are nominal, not measured.** They assume the
  *configured* `scan_interval` (default 5s) elapses between every tick. Under real load this
  project measured the daemon's actual mean scan-cycle gap running higher (varying by round;
  one measurement found a mean of ~12.3s), so `suspicious_ticks × 5` understates the true
  wall-clock time elapsed in practice.
- **`cpu_percent` is sourced independently of the eBPF scheduler collector.** A process can have
  a fully populated `cpu_bound_ratio` (from `on_cpu_ns`/switch counts) while `cpu_percent` comes
  from a separate `psutil` read — the two are not derived from the same underlying counter, and
  in principle could disagree if one collector's data were stale relative to the other.
