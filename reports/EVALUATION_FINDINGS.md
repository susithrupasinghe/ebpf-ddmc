# EDDMC — Evaluation Findings

Working notes from live testing against real cryptomining software and real
benign workloads, on the actual deployment VM (Ubuntu, aarch64, kernel
7.0.0-27-generic, 4 logical CPUs, cgroup v2). Captured for use when writing
up Chapter 6 (Results and Evaluation). Dated 2026-07-24.

---

## 1. A production-readiness bug found and fixed during this evaluation

**Symptom**: mid-test, a real XMRig instance's worker threads stopped
reporting any CPU/scheduling data, and previously-correct detections began
resetting to score 0 unexpectedly.

**Root cause**: all four eBPF collectors (`daemon/ebpf/mem_monitor.c`,
`sched_monitor.c`, `net_monitor.c`, `syscall_monitor.c`) use a fixed-capacity
BPF hash table (`#define MAX_PIDS 4096`) to store per-process behavioural
counters, and **none of them ever removed an entry when its process exited**.
The daemon's own `/api/status` showed **4515 processes tracked** after only
~2 hours of uptime on a single developer VM — already past the 4096-slot
capacity. Once a fixed-size BPF hash map is full, a kernel-side `update()`
call for a new key fails **silently** (no crash, no log line) — new
processes simply stop being tracked, or existing entries behave
inconsistently, with no visible error anywhere.

**Why this matters**: this is exactly the failure mode a long-running
production server would hit — high uptime and continuous process churn are
normal server conditions, not edge cases. A fresh daemon instance detects
correctly (as extensively verified below); the same daemon after days/weeks
of uptime would silently degrade, with no indication to the operator that
anything was wrong.

**Fix applied**: added a `TRACEPOINT_PROBE(sched, sched_process_exit)` hook
to each of the four `.c` files, deleting the exiting PID's entry from that
program's hash map:

- `mem_monitor.c`, `net_monitor.c`, `syscall_monitor.c` key their hash maps
  by **thread-group ID (TGID)** — cleanup only fires when the exiting task
  is its own thread-group leader (`pid == tgid`), so a worker thread exiting
  early doesn't wipe data still needed by sibling threads.
- `sched_monitor.c` keys its hash map by **raw thread ID (TID)**, since
  `sched_switch` populates one entry per thread — its existing exit hook
  only decremented a `thread_count` counter on the parent's entry but never
  deleted the exiting thread's *own* entry, which was the actual source of
  unbounded growth. Fixed by adding `sched_stats.delete(&tid)`.

**Verification**: restarted the daemon (fresh, 0 tracked), reran the exact
same renamed-XMRig test that had previously failed to track worker threads
— all five worker thread IDs now showed correct, substantial `on_cpu_ns`
values (11–16 billion ns, matching their real sustained CPU use), and
detection reached MEDIUM/THROTTLE on the same ~40–50 second timeline as
every other clean run.

### A related, secondary finding (not fixed, worth documenting as a limitation)

Because `sched_monitor.c` keys by **TID** while the other three collectors
key by **TGID**, a native multi-threaded process's behavioural signal is
split across multiple `process_store` entries: the TGID-keyed entry
correctly aggregates memory/syscall/network signals from *all* threads, but
its *own* CPU-time figure only reflects whatever that specific
thread-group-leader task itself does. For a process shape where the main
thread stays mostly idle while separate worker threads do all the actual
hashing (exactly XMRig's real threading model), the aggregate entry's
`cpu_percent`-dependent signals (`compute_pure`, `cpu_high`) can under-count
relative to the process's true aggregate CPU behaviour. Detection still
worked correctly in every test run via the RandomX-scratchpad and
thread-saturation signals (which are not CPU%-dependent), so this did not
prevent detection — but a properly unified per-process (not per-thread)
data model would be a more correct architecture and is worth noting as
future work.

---

## 2. Real XMRig detection results

All tests used the official Ubuntu-packaged **XMRig 6.25.0** (`apt install
xmrig`), run in `--randomx-mode=light` (the VM has ~700MB–1.4GB free RAM;
RandomX's default "fast" mode needs a ~2GB dataset). No test connected to a
real mining pool or used a real wallet address.

### 2.1 Full-speed benchmark (`xmrig --bench=5M --randomx-mode=light`)

| Time | Score | Tier | Action | Evidence |
|---|---|---|---|---|
| t=0 (first scan) | 32 | LOW | ALERT | initial futex/thread signals |
| t≈37s | 45 | MEDIUM | **THROTTLE (real, 30% CPU cap applied)** | thread saturation (5 threads = 4 logical CPUs), sustained CPU 272%, RandomX signature (19 × 2MB scratchpad allocations, 38MB total), MAP_HUGETLB ×10 |
| t≈45s onward | plateaued ~45–46 | MEDIUM | THROTTLE sustained | "sustained detection: 9 consecutive scan windows (~45s) — rules out bursty legitimate workloads" |

Once the real cgroup throttle applied, XMRig's own measured CPU% dropped
(272% → ~77–170% across repeated checks), and the score **did not escalate
further** past MEDIUM for the remainder of the run. This is a notable
self-limiting property: the mitigation itself constrains the threat's
resource consumption enough to prevent the sustained-CPU signals from
accumulating toward HIGH/CRITICAL. Worth discussing in Chapter 6 as evidence
the graduated-response design works as intended (proportionate escalation),
though also worth flagging as a discussion point: a threat that is content
to stay at 30% CPU indefinitely would remain contained at MEDIUM rather than
being fully blocked or terminated.

### 2.2 Renamed binary (behavioural vs. signature-based detection)

The same XMRig binary was copied to a new path and renamed
**`system-update-helper`**, then run with identical arguments
(`--bench=3M --randomx-mode=light`).

| Time | Score | Tier | Action |
|---|---|---|---|
| t≈49s | 45 | MEDIUM | **THROTTLE** (30% CPU cap applied) |

Detection fired on **the same behavioural signature, the same timeline,
using a process name that shares nothing with "xmrig", "miner", or any
known-bad string.** This is a direct, reproducible demonstration of the
thesis's core differentiation claim against signature/name-matching tools
(e.g. Falco's default cryptomining rules, which match on binary name or
command-line strings and are trivially defeated by renaming the binary).

### 2.3 Pool-connection signal (hard-evidence escalation)

Tested safely: a local Python TCP listener was bound to `127.0.0.1:3333`
(one of the twelve hardcoded "known mining pool" ports in
`daemon/ebpf/net_monitor.c`: 3333, 4444, 14444, 14433, 45700, 5555, 8333,
9999, 3032, 7777, 3256, 4045). XMRig was pointed at this **local, non-mining,
non-network-facing** listener via `-o 127.0.0.1:3333`, so no real mining
pool or public network infrastructure was ever contacted; the stratum
handshake was expected to (and did) fail, which is irrelevant to this test
since only the `connect()` syscall's destination port is inspected.

| Time | Score | Tier | Action |
|---|---|---|---|
| t=0 (**first scan, no waiting period**) | 55 | MEDIUM | **THROTTLE** |

7 connection attempts were correctly logged as `mining_pool_hits`. Detection
reached MEDIUM on the very first scan cycle — markedly faster than the
behaviour-only tests (which needed ~2 scan cycles / ~40–50 seconds) —
directly confirming the scorer's designed "hard evidence escalation"
principle (`scorer.py`: a confirmed pool connection sets a score floor of 50
regardless of the weighted sum of other features).

### 2.4 Evasion resistance: multi-process work-splitting

A known limitation identified in the literature review — splitting mining
work across multiple processes to dilute any single process's futex/thread
ratios below the detection threshold — was tested empirically rather than
left as a theoretical gap. Four separate single-threaded XMRig instances
were launched simultaneously (`--threads=1`, each pinned to a distinct CPU
core via `--cpu-affinity`), so that the *same total system CPU load* as one
4-threaded instance was distributed across four independent processes
instead of four threads inside one process — exactly the evasion shape
described in the literature.

**Hypothesis going in**: per-process signals such as thread-count saturation
and aggregate futex ratio would be diluted across four processes, each
looking individually less suspicious than one unified 4-thread process.

**Result**: the hypothesis did not hold. RandomX allocates its scratchpad
and initialises its cache **per process**, not proportionally to thread
count — each of the four single-threaded instances independently showed
`scratchpad_huge_allocs = 4` (the same joint size-and-hugepage signal from
§6.6, all four backed by real huge pages), and each independently reached
at least LOW confidence within one scan cycle, with three of the four
reaching MEDIUM/THROTTLE (real 30% CPU caps applied) within two scan
cycles. The fourth briefly reached MEDIUM before its own throttle's
self-limiting effect (§2.1) pulled it back to LOW in the following window —
the same pattern observed in every throttled single-process test.

**Interpretation**: splitting the workload across processes did not evade
detection — it produced *four independent detections and three concurrent
mitigations* rather than diluting one. This is because the strong signal is
tied to a per-process resource cost (RandomX's own cache/scratchpad
initialisation) that an attacker cannot avoid paying simply by
using more, smaller processes; each process still has to set up its own
RandomX state. This is a meaningfully positive result for the thesis's
robustness claims, though it should be stated precisely: this evaluation
tested *this specific* splitting strategy (N independent single-threaded
processes) on *this specific* algorithm (RandomX). It does not establish
resistance to every conceivable work-distribution strategy (for example,
an attacker splitting across *worker processes that share a single
pre-warmed RandomX dataset via shared memory*, avoiding repeated cache
initialisation, was not tested and could plausibly behave differently).

---

## 3. Benign workload baseline (false-positive check)

Two workloads chosen to be genuinely CPU-bound in ways that could plausibly
resemble mining (matching the thesis's stated benign comparison set:
cryptographic and compilation workloads):

### 3.1 OpenSSL crypto benchmark
`openssl speed -multi 4 -seconds 30 sha256 aes-256-cbc` — real,
sustained, multi-process (4 workers), CPU-bound cryptographic computation
for 30+ seconds.

**Result**: all four worker processes scored **12/NONE** throughout — well
under the LOW threshold (20). Each showed only a single partial signal
(either "thread saturation: 4 threads = 4 logical CPUs" *or* "CPU-bound:
100% involuntary preemptions"), never both together, and *zero*
RandomX-scratchpad or futex-dominance signals. Clean result.

### 3.2 Sustained parallel compilation
A synthetic 3000-function C file, compiled repeatedly for 25 seconds with 4
parallel `gcc -O3 -c` invocations running continuously (to properly exercise
the scorer's temporal/sustained-detection dimension, not just a single
few-second compile).

**Result**: zero detections at any point during the sustained 25-second
window. All `cc1` compiler processes completed with no score above NONE.

---

## 4. False positives found (five distinct real processes, across this and
   the prior session's testing)

These were not synthetic — each is a real, legitimate process on this
machine that was genuinely detected and (with real, non-dry-run mitigation
active) genuinely throttled to 30% CPU during testing.

| Process | What it is | Signal(s) that fired |
|---|---|---|
| Claude Code CLI (native binary, Bun runtime) | AI coding assistant CLI | futex + thread-saturation + RandomX-scratchpad-shaped allocations |
| VS Code (`/usr/share/code/code`) | Code editor | same class of signal |
| Electron test app's Chromium subprocess (`Chrome_ChildIOT`) | This project's own client-app, under test | "RandomX signature: 35 × 2MB scratchpad allocation(s)" |
| **`fwupd`** (`/usr/libexec/fwupd/fwupd`) | **Standard Linux firmware-update daemon** — ordinary system service, not a browser or dev tool | thread saturation + "RandomX signature: 6 × 2MB scratchpad allocation(s)"; sustained 76 consecutive scan windows (~380s) before being noticed |
| `gjs` (GNOME JavaScript) | Desktop shell component | same throttle pattern |

### Root cause, precisely identified (not just "false positives happen")

`daemon/ebpf/mem_monitor.c`'s scratchpad heuristic is:

```c
/* Exact multiple of 2MB → RandomX scratchpad */
if (len >= SCRATCHPAD_SIZE && (len % SCRATCHPAD_SIZE) == 0) {
    ms->scratchpad_allocs++;
```

Any anonymous `mmap()` whose length is an **exact multiple of 2,097,152
bytes** counts as a scratchpad allocation — with no further requirement
(e.g. co-occurring with `MAP_HUGETLB`, or occurring several times in rapid
succession alongside high futex/thread activity in the *same* short
window). 2MB is also the standard Linux **transparent huge page** size, so
*any* software that aligns large allocations to huge-page boundaries for
ordinary, unrelated performance reasons (a common, well-known optimisation
to reduce TLB misses) will trigger this exact signal. `fwupd` and
Chromium/Electron's allocators both do this independently of RandomX.

This is a concrete, fixable limitation: the scratchpad signal and its
associated hard-evidence floor (`SCRATCHPAD_FLOOR = 45`, requires only
*one* qualifying allocation plus ≥70% CPU) were too easy to trigger
for a signal billed as "one of the most specific and stable behavioural
signatures for CPU cryptomining." Two candidate fixes were identified: (a)
require `MAP_HUGETLB` set at the same time as the exact-2MB size, or (b)
require multiple scratchpad-sized allocations within a short window
combined with sustained high futex ratio, before treating it as
near-conclusive.

### Fix (a) implemented and verified

A new joint counter, `scratchpad_huge_allocs`, was added across the full
stack (`mem_monitor.c` → `mem_collector.py` → `fingerprint.py` →
`scorer.py`): it only increments when a single `mmap()` call is *both* an
exact 2MB multiple *and* flagged `MAP_HUGETLB`. The strong weight (15
points) and the hard-evidence floor now require this joint signal; a bare
size-only match (no huge-page flag) is scored as a much weaker,
non-floor-eligible signal (3 points).

**Verification 1 — false positive resolved.** Re-scoring `fwupd`'s exact
observed profile (6 scratchpad allocations, 0 with the huge-page flag, 75%
CPU, 76 sustained ticks) through the updated scorer: **score dropped from
what previously reached MEDIUM/THROTTLE to 29 (LOW/ALERT-only)** — no
longer actively mitigated, without adding `fwupd` to any exemption list.

**Verification 2 — true positive preserved.** Re-running real XMRig live
against the fixed daemon: identical detection timeline (LOW at t=0 →
MEDIUM/THROTTLE at ~40s), now correctly reporting `scratchpad_huge_allocs =
10` (confirmed matching its 10 `MAP_HUGETLB` requests exactly) and the
updated reason text "RandomX signature: 10 × 2MB scratchpad allocation(s)
backed by huge pages — strong evidence." Re-scoring XMRig's exact observed
profile with all its real signals combined (not just the memory signal in
isolation) reached HIGH/BLOCK (score 78) — the fix does not weaken true-
positive sensitivity.

This directly answers a natural objection to the original heuristic: the
fix improves precision through a more specific *behavioural* requirement
(the co-occurrence itself is what real RandomX does and incidental
allocators don't), not by exempting any specific process by name or path —
consistent with the thesis's behaviour-based detection principle.

---

## 5. Methodology notes (for the "Experimental Setup" section)

- Platform: Ubuntu, aarch64, kernel 7.0.0-27-generic, 4 logical CPUs, cgroup
  v2 unified hierarchy, ~3.3GB total RAM.
- XMRig obtained via the official Ubuntu/Debian package
  (`xmrig 6.25.0+dfsg-1`), not a downloaded binary — verifiable provenance.
- `--randomx-mode=light` used throughout due to memory constraints (light
  mode uses ~256MB for the RandomX cache vs. ~2GB+ for the full dataset in
  the default/fast mode); this is a lower-hashrate but behaviourally
  equivalent mode for the purposes of triggering the same syscall/memory/
  scheduling signals.
- No real mining pool, wallet address, or public network endpoint was ever
  contacted at any point in this evaluation.
- Real (non-dry-run) mitigation was active throughout — every THROTTLE
  action reported here was a genuine `cgroup v2 cpu.max` quota applied to a
  real process, not a simulated/logged-only decision.

---

## 6. Appendix: CPU Cryptojacking Algorithm Landscape

Background/reference material for the literature review and for justifying
the choice of RandomX/XMRig as the evaluation target in the Experimental
Setup section.

### 6.1 Dominant in real-world cryptojacking

| Algorithm | Coin(s) | CPU-friendliness detail |
|---|---|---|
| **RandomX (RX)** | Monero (XMR), since Nov 2019 | Executes random general-purpose CPU instruction sequences (integer, floating-point, branches) rather than a fixed hash function — deliberately mimics real-world code so a CPU's full instruction set becomes the "hash," making custom ASICs pointless. Also memory-hard (~2GB dataset in fast mode) to blunt GPUs. **This is the algorithm EDDMC's scratchpad-signature heuristic is built around**, and the overwhelming majority of cryptojacking today targets it. |
| **CryptoNight** (original) | Bytecoin (BCN, the original), Monero pre-2019 | RandomX's predecessor. AES-based, ~2MB "scratchpad" per thread — this is *exactly* where EDDMC's 2MB scratchpad-size heuristic originates; a CryptoNight-era signature that RandomX also happens to preserve. |
| **CryptoNight-Lite** | AEON | Reduced-memory CryptoNight variant, explicitly marketed for lower-end/mobile CPUs. |
| **CryptoNight-Heavy** | Sumokoin, Haven (as CryptoNight-XHV) | Increased-memory variant, opposite direction — heavier scratchpad, still CPU-only. |
| **CryptoNight-R / -V7 / -V8** | Various Monero-era forks and small altcoins | Incremental tweaks Monero used before adopting RandomX; still live on in smaller forks that never migrated. |

### 6.2 Explicitly ASIC/GPU-resistant, CPU-only family

Worth citing because their stated design goal — keep mining accessible to
ordinary CPUs — is the same property that makes an algorithm attractive for
cryptojacking, even where documented malware campaigns are less prominent
than Monero's:

- **yespower / yescrypt** — derived from scrypt by the same research
  lineage behind password-hashing hardening; deliberately memory-hard and
  sequential to resist GPU/FPGA/ASIC parallelism. Used by several small
  privacy-focused coins marketed explicitly as "CPU-only."
- **VerusHash** (VerusCoin) — explicitly designed and marketed as
  ASIC-resistant CPU mining; a legitimate community-mining coin, but the
  same CPU-favoring PoW property is what a cryptojacker would want if
  diversifying away from Monero.
- **Argon2-based PoW** — Argon2 is the winner of the Password Hashing
  Competition (memory-hard, tunable); a small number of coins adapted it
  directly as a proof-of-work function for the same CPU/memory-hardness
  reasons.

### 6.3 Seen in GPU-targeted cryptojacking (less common, mostly cloud/container compromises)

| Algorithm | Coin(s) | Notes |
|---|---|---|
| **Ethash / EtcHash** | Ethereum Classic (ETC); was Ethereum's pre-Merge algorithm | GPU/memory-DAG based. Was a real cryptojacking target while Ethereum was still proof-of-work (pre-Sept 2022, "The Merge"); post-Merge, only relevant for ETC and similar forks. Occasionally seen in cloud/Kubernetes cryptojacking campaigns targeting GPU-enabled instances. |
| **KawPow** | Ravencoin (RVN) | GPU-mineable, ASIC-resistant. Occasionally targeted in GPU cryptojacking. |
| **Autolykos v2** | Ergo (ERG) | GPU-mineable, has seen some cryptojacking-campaign interest. |
| **Equihash** | Zcash (ZEC) and forks | GPU/memory-hard, less commonly targeted than the above. |

### 6.4 Historical / declining relevance for CPU jacking

- **X11 / X16R / C11 chained-hash algorithms** (Dash and various altcoins)
  — CPU/GPU-mineable in their early years, largely absorbed by ASICs since.
- **Cuckoo Cycle / Cuckaroo29** (Grin) — graph-theory-based, was
  CPU/GPU-friendly before ASIC variants emerged for it too.

### 6.5 Exist but essentially irrelevant to cryptojacking

| Algorithm | Coin(s) | Why it doesn't matter for jacking |
|---|---|---|
| **SHA-256** | Bitcoin | Entirely ASIC-dominated — a stolen CPU/GPU contributes a statistically negligible hashrate, not profitable at any scale. |
| **Scrypt** | Litecoin, Dogecoin | Also largely ASIC-dominated now, though CPU/GPU-mineable in Scrypt's early years. |

### 6.6 Real-world malware families (evidence this is a live, dominant threat)

Nearly every major documented cryptojacking campaign targets Monero via
XMRig (RandomX or, in older cases, CryptoNight):

- **Smominru, WannaMine, PowerGhost** — early large-scale XMRig-based
  botnets (2017–2018 era, CryptoNight).
- **Kinsing** — targets exposed Docker/Kubernetes APIs, deploys XMRig.
- **TeamTNT** — cloud/container-focused threat actor, XMRig/Monero payloads.
- **8220 Gang, Rocke Group** — persistent threat actors specifically
  associated with XMRig deployment at scale.
- **Coinhive and its post-shutdown successors** (CoinImp, Crypto-Loot,
  deepMiner) — the browser-based (in-tab JavaScript/WASM) cryptojacking
  wave, all CryptoNight/Monero-based.

### 6.7 Why this justifies targeting RandomX/XMRig specifically

RandomX was deliberately engineered to be the best fit for stealing
ordinary CPU cycles — this is precisely why it is the correct,
highest-impact target for a CPU-cryptojacking detector, and why
GPU-oriented algorithms (Ethash, KawPow, Equihash) are a reasoned exclusion
from EDDMC's scope rather than an oversight. The narrow focus on
RandomX/CryptoNight-era signals (the 2MB scratchpad heuristic in
particular) targets the algorithm family that dominates real-world
cryptojacking, not a hypothetical or minor one.
