# EDDMC Artefact Inventory (P0-4)

Authoritative inventory of the detection artefact as it exists in code, generated to
reconcile Chapter 5's description against the actual implementation. Every claim below
carries a `file:line` citation. Git SHA this was generated against (start of the P0
evaluation work order — see `reports/EVALUATION_ROUND2.md` for the SHA of each subsequent
test run, since fixes made during this work order move the codebase forward):

```
2542b3029289ce7f979bdb06b4830a6651c9e5e0
```

---

## 0. Structural note: three non-identical feature surfaces exist

Before the per-feature table: there are **three separate feature-computation code paths**
in this repo, not one. Chapter 5 should be explicit about which one it describes.

1. **`daemon/detector/features.py`** — computes exactly the thesis's 8 named features
   (`futex_ratio`, `io_ratio`, `mmap_ratio`, `nanosleep_ratio`, `cpu_bound_ratio`,
   `thread_density`, `pool_hits`, `cpu_percent`; `features.py:10-24,74-88`).
   **This module is dead code** — grepped the entire non-`.venv` tree for any import of
   `detector.features` / `features.extract` and found zero call sites outside the file
   itself. It is not wired into `daemon/detector/engine.py` or anywhere live.
2. **`daemon/detector/fingerprint.py` + `daemon/detector/scorer.py`** — the actually-live
   pipeline, invoked from `daemon/detector/engine.py:230-231`
   (`build_fingerprint(pid, data, temp)` then `self._scorer.score(fp)`). This is what
   Chapter 6 needs to describe: it has grown past the thesis's 8 features into 6
   dataclass-grouped dimensions with 14 distinct weighted signals (§1 below).
3. **`daemon/fingerprint/packager.py`** — a *third*, separately-defined 8-element vector
   (`FEATURE_NAMES`, `packager.py:31-40`), derived from the live fingerprint but used only
   for registry submission/matching (`packager.py:43-60`), never for scoring.

**Recommendation for Chapter 5**: either document `features.py` as an earlier design
iteration superseded by the live pipeline (if that's historically accurate), or delete it
as dead code — as currently written, Chapter 5's 8-feature description matches
`features.py`, not the code that actually runs.

---

## 1. Every feature the live scorer consumes

`Scorer.score()` (`scorer.py:155-299`) reads six sub-profiles off `BehaviouralFingerprint`
(`scorer.py:160-165`), populated by `fingerprint.py:build()` (`fingerprint.py:117-191`)
from raw per-PID dicts the four collectors write into `process_store`.

| # | Signal (weight key) | Fires when | Raw source (collector → store key) | Default weight | Config key (`defaults.yaml`) | Floor-eligible? |
|---|---|---|---|---|---|---|
| 1 | `futex_strong` | futex_ratio ≥0.40 **and** cpu_percent ≥50% (`scorer.py:176-178`) | `syscall_monitor.c` → `sc["futex"]`/`["total"]` (`syscall_collector.py:73,84`) | 18 | `weights.futex_strong` | No |
| 2 | `futex_moderate` | futex_ratio ≥0.20 and cpu_percent ≥50% (`scorer.py:179-181`) | same | 9 | `weights.futex_moderate` | No |
| 3 | `compute_pure` | io_ratio <0.02 and cpu_percent ≥70% (`scorer.py:183-187`) | `sc["read"]`/`["write"]` | 10 | `weights.compute_pure` | No |
| 4 | `thread_full_sat` | thread_count ≥ cpu_count (`scorer.py:192-196`) | `sched_monitor.c` → `sched["thread_count"]` (`sched_collector.py:53-55,69-70`) | 12 | `weights.thread_full_sat` | No |
| 5 | `thread_partial_sat` | thread_count ≥0.6×cpu_count (`scorer.py:197-201`) | same | 6 | `weights.thread_partial_sat` | No |
| 6 | `cpu_high` | cpu_percent ≥85% (`scorer.py:203-205`) | **Not eBPF** — `psutil.Process(pid).cpu_percent()` (`fingerprint.py:146,197-205`) | 6 | `weights.cpu_high` | No |
| 7 | `scratchpad_exact` | scratchpad_huge_allocs >0 (`scorer.py:213-219`) | `mem_monitor.c` joint 2MB+`MAP_HUGETLB` match → `mem["scratchpad_huge_allocs"]` (`mem_collector.py:59,71`) | 15 | `weights.scratchpad_exact` | **Yes** — `scratchpad_floor` |
| 8 | `scratchpad_weak` | scratchpad_allocs >0, mutually exclusive with #7 (`scorer.py:220-225`) | size-only match → `mem["scratchpad_allocs"]` | 3 | `weights.scratchpad_weak` | No (explicit design choice, `scorer.py:20-31,82`) |
| 9 | `huge_pages` | huge_page_requests >0, independent of #7/#8 (`scorer.py:226-228`) | `mem["huge_page_requests"]` | 5 | `weights.huge_pages` | No |
| 10 | `cpu_bound_strong` | cpu_bound_ratio ≥0.92 (`scorer.py:231-236`) | `sched_monitor.c` → `sched["involuntary_switches"]`/`["voluntary_switches"]` (`sched_collector.py:67-68`) | 12 | `weights.cpu_bound_strong` | No |
| 11 | `cpu_bound_moderate` | cpu_bound_ratio ≥0.75, mutually exclusive with #10 (`scorer.py:237-239`) | same | 6 | `weights.cpu_bound_moderate` | No |
| 12 | `sustained_high` | suspicious_ticks ≥6 (~30s) (`scorer.py:242-247`) | **Not eBPF** — engine-internal counter, `TICK_THRESHOLD=20` (`engine.py:31,257-260`) | 14 | `weights.sustained_high` | No |
| 13 | `sustained_medium` | suspicious_ticks ≥3 (~15s), mutually exclusive with #12 (`scorer.py:248-252`) | same | 7 | `weights.sustained_medium` | No |
| 14 | `pool_connection` | pool_connections >0 (`scorer.py:255-260`) | `net_monitor.c` stratum-port match → `net["mining_pool_hits"]` (`net_collector.py:65-66`) | 40 | `weights.pool_connection` | **Yes** — `pool_floor`, checked first |

**Hard-evidence floors** (applied after the weighted sum, `scorer.py:262-279`):
- `pool_floor = 50` (`scorer.py:98`, `defaults.yaml:42`): `if net.pool_connections > 0: s = max(s, pool_floor)` (`scorer.py:263-264`).
- `scratchpad_floor = 45` (`scorer.py:99`, `defaults.yaml:43`): `if mem.scratchpad_huge_allocs > 0 and par.cpu_percent >= 1.0: s = max(s, scratchpad_floor)` (`scorer.py:278-279`). The CPU gate here is deliberately low (≥1%, not the ≥50-85% gates used elsewhere) — rationale documented in-code (`scorer.py:32-35,265-277`): a successfully-throttled process would otherwise show low CPU% and lose its floor eligibility purely *because* mitigation worked, causing tier flapping (a real oscillation the code comments describe having observed directly).

**Other scoring behaviour affecting every signal:**
- Youth penalty: if `age_seconds < 20.0` and score ≥60, cap at 55.0 (`scorer.py:283-286`). **This 20-second constant is hardcoded in `scorer.py` and does not read `defaults.yaml`'s `min_age_seconds: 10`** (`defaults.yaml:38`) — the two numbers disagree; the YAML key is not referenced by this code path.
- `cpu_percent` (feature #6, and the scratchpad-floor CPU gate) is the **only signal not sourced from any eBPF collector** — it is a `psutil` call.

**Fingerprint fields defined but never read by the scorer** (present in `BehaviouralFingerprint`, computed, but not consulted in `Scorer.score()`): `compute_purity`, `clone_count`, `nanosleep_ratio` (`fingerprint.py:59-61`); `thread_cpu_ratio` (`fingerprint.py:68` — used by the registry gate, §4, but not by the scorer); `total_anon_mb`, `working_set_stable`, `scratchpad_mb` (`fingerprint.py:76,78,79`); `on_cpu_ns` (`fingerprint.py:85`); `score_variance` (`fingerprint.py:95`, computed at `engine.py:262-265` but never consumed); `total_connections` (`fingerprint.py:101`).

**Internal documentation/comment inconsistencies found in `scorer.py` itself** (not editorial — these are checkable against the code's own if/elif structure):
- Line 80 comments "Memory dimension (max 23)" — but `scratchpad_exact`(15)/`scratchpad_weak`(3) are `if`/`elif` (mutually exclusive, `scorer.py:213-225`) plus independent `huge_pages`(5) → true reachable max is **20**, not 23.
- Line 85 comments "Scheduler dimension (max 16)" — `cpu_bound_strong`(12)/`cpu_bound_moderate`(6) are `elif` (mutually exclusive, `scorer.py:231-239`) with no independent add-on → true max is **12**, not 16.
- Line 64 states "Max total from all non-network features ≈ 65" — summing the actually-reachable per-dimension maxima (syscall 28 + parallelism 18 + memory 20 + scheduler 12 + temporal 14, all of which *can* co-occur for one real process) gives **92**, not ≈65, before the final `[0,100]` clamp (`scorer.py:288`). No code path was found preventing simultaneous satisfaction of all dimensions — flagging as a stale comment, not a verified enforced invariant.

---

## 2. Every eBPF C program

**Four programs, matching one Python collector each** (`daemon/collector/`). **None use
kprobes** — grepped the whole `daemon/` tree (excluding `.venv`) for
`kprobe|KProbe|attach_kprobe`; the only hit is a comment in `net_collector.py` explicitly
noting kprobes are deliberately avoided. All four attach exclusively via
`TRACEPOINT_PROBE`.

| File | Attach points | Populates |
|---|---|---|
| `syscall_monitor.c` | `TRACEPOINT_PROBE(raw_syscalls, sys_enter)` (`:77`); `TRACEPOINT_PROBE(sched, sched_process_exit)` for cleanup (`:123`) | Per-PID `syscall_stats` hash (`total, futex, mmap, mprotect, clone, nanosleep, read, write, socket, connect, send, recv, brk`, `:47-63`) polled into `store[pid]["syscall_counts"]` (`syscall_collector.py:71-84`); also streams a raw perf-buffer event per syscall (`syscall_collector.py:53-60`) |
| `sched_monitor.c` | `TRACEPOINT_PROBE(sched, sched_switch)` (`:40`); `TRACEPOINT_PROBE(sched, sched_process_fork)` (`:72`); `TRACEPOINT_PROBE(sched, sched_process_exit)` (`:92`) | Per-PID `sched_stats` (`on_cpu_ns, voluntary_switches, involuntary_switches, thread_count`, `:18-25`) polled into `store[pid]["sched"]` (`sched_collector.py:57-70`); fork/exit events also directly update `thread_count` from the perf-buffer callback (`sched_collector.py:43-55`) |
| `mem_monitor.c` | `TRACEPOINT_PROBE(syscalls, sys_enter_mmap)` (`:67`); `TRACEPOINT_PROBE(syscalls, sys_enter_mprotect)` (`:123`); `TRACEPOINT_PROBE(sched, sched_process_exit)` (`:151`) | Per-PID `mem_stats` (`total_mmap_bytes, scratchpad_allocs, scratchpad_huge_allocs, huge_page_requests, large_alloc_count, mprotect_large`, `:44-51`) polled into `store[pid]["mem"]` (`mem_collector.py:61-74`); also a perf-buffer event per large/scratchpad allocation (`mem_collector.py:42-59`) — **see the latent-bug note below** |
| `net_monitor.c` | `TRACEPOINT_PROBE(syscalls, sys_enter_connect)` (`:44`); `TRACEPOINT_PROBE(sched, sched_process_exit)` (`:90`) | `net_stats` hash tracked kernel-side (`:27-30`), but **only the perf-buffer path is read by Python** — `NetCollector` has no `_poll_bpf_maps()` at all, unlike the other three collectors. `store[pid]["net"]["total_connections"]`/`["mining_pool_hits"]` are incremented purely from the perf-buffer callback (`net_collector.py:59-74`), keyed off a hardcoded 12-port stratum list: `3333, 4444, 14444, 14433, 45700, 5555, 8333, 9999, 3032, 7777, 3256, 4045` (`net_monitor.c:20-25`) |

### Latent bug found during this inventory: narrow-window `KeyError` risk in `mem_collector.py`

`_on_mem_event()` (the perf-buffer callback, `mem_collector.py:42-59`) does:
```python
mem = self._store[pid].setdefault("mem", _empty_mem())   # line 51
...
if ev.is_scratchpad_huge:
    mem["scratchpad_huge_allocs"] += 1                    # line 59, += requires the key to pre-exist
```
`setdefault` only installs `_empty_mem()` if `self._store[pid]` has **no** `"mem"` key at
all. But `syscall_collector.py`'s `_empty_process()` — used by the *other three*
collectors when they see a new PID first — **already creates a `"mem"` sub-dict that is
missing `scratchpad_huge_allocs`** (confirmed: `syscall_collector.py:125-131` lists
`total_mmap_bytes, scratchpad_allocs, huge_page_requests, large_alloc_count,
mprotect_large` — no `scratchpad_huge_allocs`). If a PID's store row is created by
`SyscallCollector`/`SchedCollector`/`NetCollector` first, and then `_on_mem_event` fires
for that PID with `is_scratchpad_huge=1` **before** `_poll_bpf_maps()` has ever run for
that PID, line 59 raises `KeyError: 'scratchpad_huge_allocs'` inside the perf-buffer
callback thread (`mem-collector`, `mem_collector.py:87-88`) — an uncaught exception here
kills that background thread permanently (Python threads print-and-die on an unhandled
exception; nothing restarts them), silently freezing all future memory-signal updates for
**every** process, not just the one that triggered it.

**Why this has not been observed crashing during this evaluation**: `_poll_bpf_maps()`
(the periodic path, same file, `:61-74`) uses **plain assignment** on the same key
(`mem["scratchpad_huge_allocs"] = v.scratchpad_huge_allocs`, line 71) — assignment creates
the key if absent, so it is immune to this issue regardless of ordering. It runs every
~200ms in the same collector loop, right after `perf_buffer_poll()` returns
(`mem_collector.py:82-85`). Since `mem_monitor.c` updates the kernel-side `mem_stats` map
on *every* qualifying mmap (not only scratchpad-huge ones), a process almost always has at
least one ordinary mmap recorded — and therefore at least one `_poll_bpf_maps()` pass that
backfills the key — before its first scratchpad-huge-specific event arrives. The race
window is real but narrow: it requires a process's *very first* mmap event to *also* be
scratchpad-huge, with zero prior poll cycle having touched that PID. **This is a genuine,
confirmed-by-code-reading latent bug, not a hypothetical one** — but it is plausible, not
certain, that it explains any specific observed anomaly, and it was not deliberately
reproduced in this pass (would require precise timing control over event delivery).
**Recommended fix**: change `_on_mem_event`'s three `+=` lines (`mem_collector.py:52-59`)
to use `.setdefault(key, 0)` before incrementing, or make `_empty_mem()` and
`syscall_collector._empty_process()`'s `"mem"` sub-dict identical.

---

## 3. Tier boundaries and mitigation actions, as implemented

### Tier boundaries (`scorer.py:102-115`, `defaults.yaml:21-32`)

| Tier | Config key | Threshold (inclusive lower bound) |
|---|---|---|
| NONE | — | score <20 |
| LOW | `alert_threshold` | 20 |
| MEDIUM | `throttle_threshold` | 40 |
| HIGH | `block_threshold` | 60 |
| CRITICAL | `terminate_threshold` | 80 |

### Mitigation cascade, confirmed against `daemon/mitigator/policy.py`

- **ALERT (LOW, ≥20)**: log + alert callback only (`policy.py:66-71`). No throttle.
- **THROTTLE (MEDIUM, ≥40)**: real cgroup v2 `cpu.max` quota. Confirmed:
  `{"MEDIUM": 30, "HIGH": 10, "CRITICAL": 5}` percent (`throttler.py:82`), matching
  `defaults.yaml:99-102`'s `throttle_quotas` — **but that YAML block is not itself read**;
  the percentages are hardcoded a second time in `throttler.py:82`. Currently in
  agreement, but two sources of truth, not one.
- **BLOCK (HIGH, ≥60)**: cascade is additive (throttle stays applied) plus a real iptables
  rule: `iptables -I OUTPUT 1 -m cgroup --path eddmc/<pid> -j DROP` (`blocker.py:67-72`),
  cgroup-v2-scoped rather than UID/net_cls-based. Fails closed — does not fall back to a
  broader block if the cgroup-scoped rule can't be applied (`blocker.py:74-86`).
- **CRITICAL (≥80)**: **always** sends `SIGSTOP` (`suspender.py:16-27`). `SIGKILL` only if
  `auto_kill: true` (default `false`) — and even then it is `SIGTERM` → 3s grace →
  liveness check → `SIGKILL` only if still alive (`terminator.py:20-41`), never a bare
  `SIGKILL`. The `sigterm_grace: 3` YAML key (`defaults.yaml:105`) is likewise not read;
  3.0 is hardcoded in `terminator.py:20` (currently in agreement, same pattern as above).
- `dry_run` (default `false`): short-circuits before any of the above; logs `[DRY-RUN]`
  and calls the alert callback with `dry_run: True` (`policy.py:60-64`).
- Escalation is monotonic per process — mitigation only re-dispatches on a tier increase
  (`engine.py:289-295`), not every scan tick.
- Revocation (`policy.py:94-107`) unconditionally calls unblock/unthrottle/resume when a
  mitigated PID exits, triggered from `engine.py`'s `on_process_gone` callback.

---

## 4. Fingerprint registry confirmation gate — exact conditions

`FingerprintAssessor.evaluate()` (`daemon/fingerprint/assessor.py:36-69`), called once per
scan tick per scored process.

**Gate 1** (checked first, unconditionally): `result.confidence` must literally equal the
string `"CRITICAL"` (score ≥80). Any tick below CRITICAL resets the sustained-streak timer
entirely (`assessor.py:43-49`) — the streak must be continuous, not cumulative.

**Gate 2** (only reached if Gate 1 passes), quoted verbatim from `assessor.py:54-63`:
```python
cond_sustained = sustained >= self._sustained_s
cond_pool = net.pool_connections > 0
cond_features = (
    sc.futex_ratio >= STRONG_FUTEX_RATIO
    and sch.cpu_bound_ratio >= STRONG_CPU_BOUND_RATIO
    and par.thread_cpu_ratio >= STRONG_THREAD_DENSITY
)
if not (cond_sustained and cond_pool and cond_features):
    return None
```
Constants (`assessor.py:26-28,32`): `STRONG_FUTEX_RATIO=0.40`, `STRONG_CPU_BOUND_RATIO=0.92`,
`STRONG_THREAD_DENSITY=1.0`, `sustained_s=60.0` (from
`fingerprint_registry.sustained_critical_seconds: 60`, `defaults.yaml:131`).

A fourth item — best-effort binary hashing (`assessor.py:68`) — is included in the
returned evidence dict but is **not gating**: absence of a hash never blocks submission
(`assessor.py:14-16`).

### Direct assessment of the "structurally unreachable" hypothesis

**Confirmed, and the actual gate is stricter than the stated hypothesis:** it is not
merely "score ≥80 for 60s" — it is **score ≥80 continuously for 60s, AND a confirmed pool
connection, AND futex_ratio ≥0.40 AND cpu_bound_ratio ≥0.92 AND thread_cpu_ratio ≥1.0, all
simultaneously, for the full 60-second window.** Reaching CRITICAL via the score floors
alone (`pool_floor=50`, `scratchpad_floor=45` — both land inside MEDIUM, `[40,60)`) does
not imply any of the three feature thresholds in Gate 2 are met; they are independent
checks, not derived from the score. Whether observed XMRig runs' 45-46 plateau is directly
*caused* by the scratchpad floor specifically was not traced to a live per-tick weight
breakdown in this pass (see P0-1 for that instrumentation) — flagging as a plausible,
code-consistent inference, not an independently re-verified causal chain in this document.

---

## 4.5 `thread_density` vs `thread_cpu_ratio` — the specific conflict, resolved

**The dissertation's `thread_density` name is not used anywhere in the live scoring
pipeline.** There are, in fact, three distinct code paths touching this concept, not two:

1. **`daemon/detector/features.py`** (`features.py:67-68,82`) is the *only* place the exact
   name `thread_density` and the dissertation's own formula both appear:
   `thread_density = min(thread_count / cpu_count, 2.0) / 2.0` — deliberately normalised to
   `[0, 1]`. This module is dead code (§0 above): zero live call sites.
2. **`daemon/detector/fingerprint.py:68,149`** (the live pipeline) computes
   `thread_cpu_ratio = min(threads / cpu_count, 2.0)` — the same core ratio, but *without*
   the `/2.0` step, so its range is `[0, 2]`, not `[0, 1]`. **`Scorer.score()` does not read
   this field at all** — the scorer's own thread-saturation gates
   (`scorer.py:192-201`, `thread_full_sat`/`thread_partial_sat`) compare the raw
   `par.thread_count` against `cpu_count` directly, inline, never going through
   `thread_cpu_ratio` or any name resembling `thread_density`.
3. **`daemon/fingerprint/assessor.py:59`** (registry confirmation gate — not the scorer)
   reads `par.thread_cpu_ratio >= STRONG_THREAD_DENSITY` (constant named `STRONG_THREAD_DENSITY`,
   value `1.0`, `assessor.py:28`) — correct attribute name, but a constant name that imports
   the dissertation's "density" terminology into code that actually gates on the
   *unnormalised* `[0, 2]` ratio, not a `[0, 1]` density.

**An additional divergence found while resolving this, not previously flagged:**
`daemon/fingerprint/packager.py:36,56` — the registry-submission feature vector — uses the
string key `"thread_density"` in its `FEATURE_NAMES` list, but assigns it
`min(par.thread_cpu_ratio, 2.0)`, i.e. **fingerprint.py's un-normalised `[0, 2]` value,
re-labelled under the dissertation's `[0, 1]`-implying name at the one place in the
codebase where that exact string is emitted outward** (into the registry payload another
node's matcher would compare against). This is a real naming/normalisation mismatch in the
registry-submission path specifically — not merely a documentation gap — and should be
corrected (either rename the packager's key to `thread_cpu_ratio`, or apply the same `/2.0`
normalisation `features.py` uses before assigning it) before the registry channel is relied
upon for the P0-1 two-node experiment, since two nodes comparing a field under a shared
name that means two different scales would corrupt the cosine-similarity match.

**For Chapter 5/6: state that the live scorer has no `thread_density` feature at all** —
thread saturation is scored from the raw thread/CPU-core comparison directly. `thread_density`
survives only as a name in dead code (`features.py`) and, inconsistently normalised, in the
registry packager's export key.

## 5. Summary of divergences from thesis Chapter 5, for direct correction

| Thesis claim | Actual code | Action needed |
|---|---|---|
| 8 features: `futex_ratio, io_ratio, cpu_bound_ratio, thread_density, mmap_ratio, nanosleep_ratio, pool_hits, cpu_percent` | Live scorer uses 14 weighted signals across 6 dimensions (§1); the exact 8-feature set exists only in dead code (`features.py`) | Rewrite §5.5.2 to describe the live pipeline, or explicitly frame `features.py` as a superseded design iteration |
| 3 eBPF C programs | 4 (`syscall_monitor.c`, `sched_monitor.c`, `mem_monitor.c`, `net_monitor.c`) — `mem_monitor.c` undocumented | Add `mem_monitor.c` to §5.5.1 |
| Table 2: MEDIUM = 30% cgroup throttle, HIGH = network block | Confirmed correct as implemented (§3 above) | No change needed |
| §5.5.4 mitigations are reversible | Confirmed — `policy.py:94-107` unconditional revoke | No change needed, but effect (not just application) is unmeasured — see P1-2 |
| Registry accelerates cross-deployment detection (RQ6, Objective 7) | Confirmation gate has never been empirically shown to fire; requires CRITICAL+pool+3 feature thresholds sustained 60s simultaneously, stricter than commonly assumed | See P0-1 investigation/decision, tracked separately |
| `thread_density` (dissertation name) | Live scorer uses raw `thread_count` vs `cpu_count` directly, no ratio field at all; `thread_cpu_ratio` (unnormalised `[0,2]`) exists only for the registry gate; `packager.py` mislabels that unnormalised value as `"thread_density"` in registry submissions | See §4.5 above — rename/renormalise the packager key before relying on cross-node registry comparison |
