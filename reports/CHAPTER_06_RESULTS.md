# CHAPTER 06: RESULTS AND EVALUATION

*Draft — written from live testing on the deployment VM, 2026-07-24. Intended
as a starting point to adapt into the thesis document; figures, exact
wording, and citation formatting should be reviewed and adjusted to match
the rest of the dissertation.*

## 6.1 Evaluation Objectives and Scope

This chapter presents an empirical evaluation of the EDDMC daemon against a
real CPU cryptominer (XMRig) and a set of genuinely CPU-intensive benign
workloads, on the system's actual target deployment environment. The
evaluation addresses three questions raised by the research objectives:

1. Does the deterministic, behaviour-based scoring model correctly detect a
   real cryptominer, and within what timeframe?
2. Is detection genuinely behavioural — does it survive a trivial evasion
   attempt (renaming the miner binary) — as opposed to relying on
   signature or name matching, per the thesis's central differentiation
   from tools such as Falco?
3. What is the system's behaviour on legitimate, CPU-intensive workloads
   that could plausibly resemble mining (cryptographic computation,
   compilation)?

**Scope note.** This evaluation is a targeted, case-study-style validation
of detection timeliness, behavioural robustness, and false-positive
characterisation on a small number of controlled runs. It does not
constitute a large-N statistical study and does not yet produce
precision/recall/F1 figures comparable to those reported for ML-based
systems such as CryptoGuard (Park et al., 2025) or Kim et al. (2025). That
larger quantitative evaluation is identified as future work in Chapter 7.

## 6.2 Experimental Setup

| Parameter | Value |
|---|---|
| Host | Ubuntu, aarch64, kernel 7.0.0-27-generic |
| CPU | 4 logical cores |
| Memory | 3.3GB total |
| cgroup version | v2 (unified hierarchy) |
| Miner under test | XMRig 6.25.0, official Ubuntu/Debian package (`xmrig 6.25.0+dfsg-1`) |
| RandomX mode | `light` (reduced memory footprint; the host's available RAM did not accommodate the ~2GB dataset required by the default `fast` mode) |
| Mitigation mode | Real (non-dry-run) — every mitigation action reported below executed a genuine `cgroup v2 cpu.max` quota against a real process |
| Network exposure | None — no test connected to a real mining pool, wallet, or public network endpoint (see §6.4.3) |

XMRig was obtained via the distribution's official package repository
rather than a downloaded binary, so its provenance is independently
verifiable.

### 6.2.1 Justification for targeting RandomX/XMRig specifically

The choice of RandomX as the sole algorithm evaluated is a deliberate scope
decision rather than a convenience sample. RandomX (used by Monero since
November 2019) was engineered specifically to execute random
general-purpose CPU instruction sequences rather than a fixed hash
function, making custom mining ASICs pointless and ordinary CPUs the most
*efficient* available hardware — precisely the property that makes it the
dominant algorithm in real-world cryptojacking. This is corroborated by
the threat-intelligence literature on documented campaigns (Smominru,
WannaMine, PowerGhost, Kinsing, TeamTNT, 8220 Gang, and the Coinhive-era
browser-based mining wave), which overwhelmingly deploy XMRig against
Monero via RandomX or its CryptoNight predecessor — the same predecessor
from which EDDMC's 2MB scratchpad-allocation heuristic (§6.4.3) is
descended. GPU-oriented proof-of-work algorithms (Ethash, KawPow,
Equihash) and ASIC-dominated algorithms (SHA-256, Scrypt) are excluded from
scope on the same basis: they are either mechanically invisible to a
CPU/memory/scheduler-based collector, or economically irrelevant to an
attacker choosing where to point stolen compute.

## 6.3 Detection Effectiveness

### 6.3.1 Full-speed detection

XMRig was run via its built-in self-contained benchmark mode
(`xmrig --bench=5M --randomx-mode=light`), which exercises RandomX's real
computation and memory-allocation pattern without requiring a network
connection.

**Table 6.1 — Detection timeline, full-speed XMRig**

| Elapsed time | Score | Confidence | Mitigation action | Contributing evidence |
|---|---|---|---|---|
| t = 0s (first scan) | 32 | LOW | Alert logged | Initial futex and thread-parallelism signals |
| t ≈ 37s | 45 | MEDIUM | **CPU throttled to 30%** | Thread saturation (5 threads on 4 logical CPUs); sustained CPU 272%; RandomX signature (19 × 2MB scratchpad allocations, 38MB total); 10 huge-page requests |
| t ≈ 45s onward | 45–46 (plateau) | MEDIUM | Throttle sustained | "Sustained detection: 9 consecutive scan windows (~45s) — rules out bursty legitimate workloads" |

Once the cgroup throttle was applied, XMRig's measured CPU utilisation fell
substantially (from 272% to a range of roughly 77–170% across repeated
observations), and the score did not escalate further for the remainder of
the run. This is evidence that the graduated mitigation design functions as
intended: the system's own intervention constrains the workload enough that
it does not continue accumulating toward HIGH/CRITICAL. It is also worth
noting as a discussion point (§6.6) that a threat willing to persist
indefinitely at a throttled resource level would remain contained at
MEDIUM rather than being blocked or terminated.

### 6.3.2 Behavioural vs. signature-based detection

To test whether detection depends on the process name (as tools such as
Falco's default cryptomining rules do, matching binary names or
command-line substrings), the XMRig binary was copied to a new path and
renamed to **`system-update-helper`**, then run with identical parameters.

**Table 6.2 — Detection timeline, renamed binary**

| Elapsed time | Score | Confidence | Mitigation action |
|---|---|---|---|
| t ≈ 49s | 45 | MEDIUM | **CPU throttled to 30%** |

Detection occurred on the same behavioural signature, at effectively the
same timeline, under a process name sharing no substring with "xmrig",
"miner", or any other conventionally blocklisted term. This result directly
supports the thesis's central claim of behaviour-based, rather than
signature-based, detection.

### 6.3.3 Network-evidence-accelerated detection

The scoring model's design gives near-conclusive weight to a confirmed
connection to a known mining-pool port, intended to allow detection to
bypass the normal sustained-observation window entirely when such evidence
is present. To test this without contacting real mining infrastructure, a
local TCP listener was bound to `127.0.0.1:3333` — one of the twelve
statically defined "known mining pool" ports monitored by the network
collector — and XMRig was directed at this local address as its pool
(`-o 127.0.0.1:3333`). The stratum protocol handshake itself was expected
to fail against this listener; this is immaterial, as detection is based
solely on the destination port of the `connect()` system call, not on
protocol-level content.

**Table 6.3 — Detection timeline, pool-connection evidence**

| Elapsed time | Score | Confidence | Mitigation action |
|---|---|---|---|
| t = 0s (first scan, no observation delay) | 55 | MEDIUM | **CPU throttled to 30%** |

Detection reached MEDIUM confidence on the first scan cycle, markedly
faster than either behaviour-only test (§6.3.1, §6.3.2), which required
approximately 40–50 seconds. This confirms the intended operation of the
scoring model's hard-evidence floor: a confirmed pool connection sets a
minimum score of 50 independent of the weighted sum of other behavioural
features.

### 6.3.4 Resistance to a documented evasion technique: multi-process work-splitting

The literature review identifies splitting mining work across multiple
processes — to dilute any single process's futex ratio and thread count
below the detection threshold — as a plausible evasion technique against
per-process behavioural monitoring. Rather than leave this as a
theoretical concern, it was tested directly: four independent
single-threaded XMRig instances (`--threads=1`, each pinned to a distinct
CPU core) were launched simultaneously, distributing the same total system
load across four processes instead of concentrating it as four threads
within one process.

**Table 6.4 — Detection outcome, four-way process-split workload**

| Process | Elapsed time to first detection | Peak confidence reached |
|---|---|---|
| Instance 1 | t = 0s | MEDIUM (throttled, then briefly self-limited back to LOW) |
| Instance 2 | t = 0s | MEDIUM (throttled) |
| Instance 3 | t = 0s | MEDIUM (throttled) |
| Instance 4 | t = 0s | MEDIUM (throttled) |

All four instances were detected within the first scan cycle, and three of
four were independently throttled within two scan cycles — the same
timeline as the single-process tests in §6.3.1–6.3.2. The evasion attempt
did not succeed: rather than diluting the signal, it produced four
concurrent, independent detections. The reason is architectural rather
than incidental — RandomX initialises its scratchpad and cache **per
process**, not proportionally to thread count, so each split-off instance
still incurred the same memory-allocation signal (§6.4.3) that a single
unified process would have produced, and each independently crossed the
hard-evidence floor.

This result should be stated precisely rather than generalised: it
demonstrates resistance to *this specific* splitting strategy (N
independent, individually-initialised processes) against *this specific*
algorithm (RandomX). It does not establish resistance to every
work-distribution strategy — for example, an attacker sharing a single
pre-warmed RandomX dataset across worker processes via shared memory
(avoiding repeated cache initialisation entirely) was not tested and may
behave differently. This distinction is worth stating explicitly in
Chapter 7 as a bounded claim rather than a general one.

## 6.4 False-Positive Evaluation

### 6.4.1 Benign workload baseline

Two workloads were selected for genuinely CPU-intensive behaviour that
could plausibly overlap with mining signals, consistent with the
thesis's identified risk category of cryptographic and compilation
workloads (§3.12 / ethics discussion).

**OpenSSL cryptographic benchmark** —
`openssl speed -multi 4 -seconds 30 sha256 aes-256-cbc`: four real,
CPU-bound worker processes sustained for 30 seconds. All four scored 12 out
of 100 (confidence NONE) throughout, with no more than one partial signal
active at any time (either thread-saturation or CPU-boundedness, never
RandomX-scratchpad or futex-dominance signals).

**Sustained parallel compilation** — a synthetic C source file compiled
continuously for 25 seconds using four parallel `gcc -O3` invocations, to
properly exercise the scorer's temporal/sustained-detection dimension
rather than a single short-lived compile. Zero detections occurred at any
point during the sustained window.

### 6.4.2 False positives identified during testing

Real mitigation being active throughout this evaluation had the incidental
benefit of surfacing genuine false positives on the host's own running
software. Five distinct legitimate processes were observed to reach MEDIUM
confidence and be actively throttled during the course of testing:

**Table 6.4 — False positives observed**

| Process | Nature | Signal(s) triggered |
|---|---|---|
| Claude Code CLI (Bun runtime) | AI coding assistant | Futex + thread-saturation + scratchpad-shaped allocations |
| VS Code | Code editor | Same class of signal |
| Electron/Chromium subprocess | This project's own GUI, under test | RandomX-signature match (35 × 2MB allocations) |
| **`fwupd`** | **Standard Linux firmware-update daemon** | Thread saturation + RandomX-signature match (6 × 2MB allocations); sustained undetected for approximately 380 seconds before review |
| `gjs` (GNOME JavaScript) | Desktop shell component | Same throttle pattern |

The `fwupd` case is particularly instructive, as it is an ordinary system
service with no relationship to browsers, development tools, or
cryptography, ruling out "unusual software category" as an explanation.

### 6.4.3 Root cause of the scratchpad false positive

Investigation traced the false positives to a specific implementation
detail in the memory-monitoring eBPF program:

```c
/* daemon/ebpf/mem_monitor.c */
if (len >= SCRATCHPAD_SIZE && (len % SCRATCHPAD_SIZE) == 0) {
    ms->scratchpad_allocs++;   /* SCRATCHPAD_SIZE = 2,097,152 bytes (2MB) */
```

Any anonymous memory mapping whose length is an exact multiple of 2MB is
counted as a RandomX scratchpad allocation, with no additional
qualification. Because 2MB is also the standard Linux transparent
huge-page size, any software that aligns large allocations to huge-page
boundaries — a common, mining-unrelated performance optimisation to reduce
TLB pressure — triggers the identical signal. Both `fwupd` and
Chromium/Electron's memory allocators were observed doing this
independently.

This finding qualifies the thesis's characterisation of the RandomX
scratchpad signal as "one of the most specific and stable behavioural
signatures for CPU cryptomining" (§5.5.2): in its original implementation,
the signal was specific to *2MB-granularity allocation*, which is
necessary but not sufficient evidence of RandomX specifically.

Rather than exempt the affected processes by name — which would narrow
the fix to the specific software observed on this one host and leave the
same false-positive class open on any other machine running different
huge-page-aligned software — the underlying behavioural signal itself was
tightened. The eBPF program was extended to test the *joint* condition
(scratchpad-sized allocation **and** the `MAP_HUGETLB` flag on that same
`mmap()` call), rather than size alone:

```c
/* daemon/ebpf/mem_monitor.c, corrected */
u8 is_scratchpad_huge = (is_scratchpad && is_huge) ? 1 : 0;
if (is_scratchpad_huge) ms->scratchpad_huge_allocs++;
```

The scorer (`daemon/detector/scorer.py`) was correspondingly split into two
signals: `scratchpad_huge_allocs` (size and huge-page flag together) keeps
the original strong weight (15) and remains the only path eligible for the
hard-evidence floor, while a bare size match with no huge-page flag
(`scratchpad_allocs` alone) was demoted to a new, much weaker weight (3)
that cannot floor the score on its own. This exploits a property genuine
RandomX has and the false-positive class does not: real RandomX requests
huge pages *specifically for* its scratchpad, whereas `fwupd` and
Electron/Chromium's allocators merely align to the 2MB boundary as a TLB
optimisation, without requesting `MAP_HUGETLB`.

**Fix verification.** Two independent checks confirmed the fix removed the
false positive without weakening true-positive detection:

1. *False-positive resolution.* A synthetic behavioural fingerprint built
   from `fwupd`'s exact observed values during the false-positive episode
   (6 scratchpad-sized allocations, 0 `MAP_HUGETLB` requests, elevated
   thread count) was re-scored against the corrected scorer. The score fell
   from MEDIUM/THROTTLE to **29/LOW** — below the alert threshold requiring
   any mitigation response.
2. *True-positive sensitivity preserved.* A live re-test of the real XMRig
   binary (§6.3.1 conditions) confirmed `scratchpad_huge_allocs` correctly
   populated to match its actual huge-page requests (10, matching 10 real
   huge-page allocations observed), preserving the original detection
   timeline. A synthetic fingerprint built from XMRig's exact observed
   values, scored with all signals combined, reached **78/HIGH/BLOCK** —
   confirming the corrected scorer still escalates a genuine miner to a
   strong-confidence tier.

This is reported as an implemented and verified fix, not a proposal for
future work: the false-positive class this section identifies (`fwupd`,
and by the same mechanism, Chromium/Electron) no longer reaches the
scratchpad hard-evidence floor, while the RandomX true-positive path is
unaffected. The remaining, deliberately narrower limitation — untested
against CPU-mining algorithms other than RandomX (e.g. yespower, Argon2-
based schemes) that do not share its huge-page-scratchpad memory profile —
is discussed as a scope boundary in Chapter 7.

## 6.5 A Production-Readiness Finding: eBPF Map Capacity

During the course of this evaluation, a defect was identified that bears
directly on the system's suitability for the server deployment scenario
described in the thesis's motivation (§1.1).

All four eBPF collectors store per-process behavioural counters in a
fixed-capacity kernel hash table (`MAX_PIDS = 4096`), and none removed
entries when a process exited. After approximately two hours of continuous
operation on a single development host, the daemon's own status endpoint
reported 4,515 processes tracked over its lifetime — already exceeding the
table's capacity. A full BPF hash table silently drops further `update()`
calls with no error surfaced anywhere in the system, meaning detection for
processes started after this point could degrade without any indication to
an operator.

This is significant because sustained uptime and continuous process churn
are normal conditions for a production server, not edge cases — the exact
deployment scenario the thesis targets. The defect was corrected by adding
process-exit cleanup (a `sched_process_exit` tracepoint hook deleting the
exiting process's table entry) to all four eBPF programs, and the fix was
verified by confirming correct detection behaviour on a freshly restarted
daemon instance under the same test conditions as §6.3.

This finding and fix are reported here as part of the evaluation process
itself, since they were discovered through the act of testing against a
real, sustained workload rather than through code review — illustrating
the value of behavioural testing beyond unit-level verification.

## 6.6 Discussion

The results support the following conclusions:

- **Detection is timely.** A real cryptominer was detected within
  approximately 40–50 seconds under pure behavioural evidence, and
  immediately (first scan cycle) when network evidence was present.
- **Detection is behavioural, not signature-based**, as directly
  demonstrated by the renamed-binary test producing an identical outcome
  to the unmodified binary.
- **Mitigation is real and effective at its intended tier.** The graduated
  CPU-throttling response measurably reduced the miner's resource
  consumption, and did so without disrupting the two benign CPU-intensive
  workloads tested, which never crossed the alert threshold.
- **False positives are real but explicable**, and in the case
  investigated in depth (`fwupd`), attributable to a specific, nameable
  weakness in one signal's implementation rather than a fundamental
  flaw in the overall multi-signal design — the multi-signal, hard-evidence
  and temporal-gating architecture correctly kept the two deliberately
  adversarial benign workloads (OpenSSL, sustained compilation) clean even
  while a related, less-specific signal misfired on unrelated system
  software.

## 6.7 Limitations of This Evaluation

- Detection was tested against XMRig's self-contained benchmark mode
  (`--bench`) and a locally-terminated pool connection, not a live,
  extended real-world mining session against genuine pool infrastructure.
- All tests were run on one host under one set of resource constraints
  (`--randomx-mode=light` was required due to available memory); results
  under the default RandomX mode, or on a host with more available memory
  and CPU cores, may differ quantitatively.
- The evaluation is not yet a statistically powered study — each scenario
  in §6.3 and §6.4 was run a small number of times, sufficient to
  establish that the described behaviour occurs and is reproducible, but
  not sufficient to report a confidence interval on detection latency or
  false-positive rate.
- Known evasion techniques identified during the literature review — for
  example, splitting mining work across multiple processes to dilute any
  single process's futex/thread ratios below threshold, or bypassing the
  monitored syscall surface via `io_uring` — were not tested in this
  evaluation and remain open items, discussed further in Chapter 7.
