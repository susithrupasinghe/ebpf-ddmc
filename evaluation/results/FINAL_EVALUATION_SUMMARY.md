# EDDMC — Final Evaluation Summary (for Results & Evaluation chapter)

This document consolidates two evaluation sessions (2026-07-24 and 2026-07-26/28)
into one handoff reference: every number, table, and finding needed to write the
thesis's Results and Evaluation chapter. Source data: `evaluation/results/*.csv`
(auto-generated, this session) and `reports/EVALUATION_FINDINGS.md` (prior
session's manual testing). Nothing here is invented — every figure traces back
to a CSV or a directly-observed log line.

---

## 1. Experimental setup

- Platform: Ubuntu, `aarch64`, kernel `7.0.0-27-generic`, 4 logical CPUs, cgroup v2 unified hierarchy
- XMRig: official Ubuntu/Debian package `6.25.0+dfsg-1` (not a downloaded binary — verifiable provenance)
- Mitigation mode: **live** (`dry_run=false`) throughout both sessions — every THROTTLE recorded below is a real `cgroup v2 cpu.max` quota applied to a real process, independently verified against `/sys/fs/cgroup/eddmc/<pid>/cpu.max`, not a simulated/logged-only decision
- No real mining pool, wallet address, or public network endpoint was contacted at any point
- Session 2 tracks share one capture instrument (`evaluation/results_capture.py`) polling the daemon's `/api/processes` API at 1-2s intervals

---

## 2. Detection & mitigation summary — all scenarios, both sessions

| # | Scenario | Session | Detected? | Peak score | Tier | Mitigated (real enforcement)? | Time to alert |
|---|---|---|---|---|---|---|---|
| 1 | XMRig full-speed benchmark (`--bench=5M`, light mode) | 1 | ✅ | 45-46 | MEDIUM | ✅ THROTTLE (30% quota) | t≈0s (first scan, LOW) |
| 2 | XMRig renamed to `system-update-helper` | 1 | ✅ | 45 | MEDIUM | ✅ THROTTLE | t≈49s |
| 3 | Pool-connection signal (local listener, port 3333) | 1 | ✅ | 55 | MEDIUM | ✅ THROTTLE | t=0s (first scan) |
| 4 | Multi-process evasion (4× single-threaded XMRig, CPU-pinned) | 1 | ✅ 4/4 | ≥LOW all 4 | 3× MEDIUM, 1× LOW (self-limited) | ✅ 3/4 THROTTLE | within 1-2 scan cycles |
| 5 | Benign: OpenSSL `speed -multi 4` | 1 | ✅ correctly quiet | 12/NONE (×4 workers) | NONE | N/A (true negative) | never |
| 6 | Benign: sustained parallel `gcc -O3` compile | 1 | ✅ correctly quiet | 0/NONE | NONE | N/A (true negative) | never |
| 7 | XMRig ground truth (`--bench=1M`) | 2 | ✅ | 45.0-46.0 | MEDIUM | ✅ THROTTLE | 54.9-77.2s |
| 8 | Self-throttled miner evasion (1 thread, `--bench=3M`) | 2 | ✅ | 45.0 | MEDIUM | ✅ THROTTLE | 27.7-79.6s |
| 9 | UPX-packed XMRig binary | 2 | ✅ | 46.0 | MEDIUM | ✅ THROTTLE | 28.2-81.7s |
| 10 | Browser WASM miner (Puppeteer) | 2 | ✅ | 39.0 (an earlier, overwritten run also reached 15.0/NONE — noted for run-to-run variance) | LOW | ❌ ALERT only, below THROTTLE threshold | 55.8s |
| 11 | Network pool-hits (stratum port, mock listeners) | 2 | ⚠️ inconsistent — see §5 | 0 or 50.0 | NONE or MEDIUM | 0/3 official trials, ✅ in 2 isolated demonstrations | 14.0s when it fires |
| 12 | Benign: OpenSSL (3 trials) | 2 | ✅ correctly quiet | 4.0 ± 6.9 | NONE | N/A (true negative) | never |
| 13 | Benign: sustained parallel `gcc` compile (3 trials) | 2 | ✅ correctly quiet | 0.0 ± 0.0 | NONE | N/A (true negative) | never |
| 14 | Real MalwareBazaar sample (XMRig-derived, confirmed via `strings`) | 2 | **Not evaluated by eBPF** — identified via static analysis only | N/A | N/A | N/A | N/A |

### Headline tallies

- **Distinct cryptojacking scenarios where EDDMC's eBPF mechanism was actually exercised: 9** (rows 1-4, 7-11 above; row 14 excluded — see §4)
- **Detected (reached at least an alert-tier confidence) at least once across all runs of that scenario: 9/9** — for row 11 (pool-hits), this counts the 2 isolated demonstrations as legitimate evidence; the official 3-trial run alone showed 0/3, disclosed honestly in §5
- **Mitigated with real enforcement (cgroup throttle actually applied) at least once: 8/9** — every scenario except browser-WASM (row 10), which stayed at ALERT tier (below the THROTTLE threshold) in every run
- **False positives across all benign baselines (2 sessions, 5 distinct benign trial-sets): 0** — every benign workload correctly stayed at NONE/very-low score

---

## 3. Evasion resistance — what was specifically tried, and the result

| Evasion technique | Result | Why it failed against EDDMC |
|---|---|---|
| Rename binary (`xmrig` → `system-update-helper`) | Detected identically (MEDIUM/THROTTLE, same timeline) | Detection is purely behavioural — no name/string matching anywhere in the scorer |
| UPX packing (4.0MB → 1.4MB, verified `linux/arm64`) | Detected identically (46.0/MEDIUM/THROTTLE) | Signals are observed *after* the UPX stub unpacks in memory — packing affects the on-disk layout, not runtime behaviour |
| Reduce thread count to 1 (evade thread-saturation signal) | **Partially succeeded, then still caught**: `thread_full_sat` signal did not fire (1 thread < 4 cores), but the RandomX scratchpad+huge-page hard-evidence floor (`scratchpad_floor=45`) forced MEDIUM anyway at t=43.8s | RandomX's memory signature (2MB scratchpad + `MAP_HUGETLB`) is initialised once per process regardless of thread count — thread-count evasion doesn't touch this signal at all |
| Split work across 4 independent single-threaded processes instead of 1 multi-threaded process | **Did not evade** — produced 4 independent detections instead of diluting 1 | Each process independently pays RandomX's own cache/scratchpad initialisation cost; splitting doesn't reduce this per-process cost, so each instance still trips the signature |

**Not tested** (named explicitly, not just omitted): a shared, pre-warmed RandomX dataset across worker processes via shared memory (would avoid repeated cache initialisation — plausibly behaves differently, never implemented to verify).

---

## 4. Real-world malware sample — case study

A genuine MalwareBazaar sample was fetched and tested (not a synthetic/self-run XMRig instance), producing a result more valuable than a detection score: **a directly observed real attack behaviour**.

- **Fetched**: 5 samples tagged `CoinMiner` from MalwareBazaar (API-key-authenticated, AES-encrypted zips, password `infected`)
- **Architecture filter**: 1 Windows PE (out of scope — no Windows agent), 4 ELF. Of the 4 ELF samples, only **1 matched this test VM's architecture** (`aarch64`) — the other 3 were x86-64, i386, and ARM32, with no emulator available to run them. This is itself a notable, honestly-reportable limitation of single-VM testing against a multi-architecture malware corpus.
- **Identification**: static analysis (`strings`) on the one runnable sample (sha256 `c6a35e65...`) found literal XMRig source strings (`donate.ssl.xmrig.com`, `donate.v2.xmrig.com`, `no active pools, stop mining`) — **confirmed to be an XMRig-derived binary**, consistent with the well-documented real-world pattern that most cryptojacking "malware" is unmodified or lightly-modified XMRig deployed without consent.
- **Security incident (real, not simulated)**: on its first execution — run under an earlier version of the test harness that gave it full root privileges for namespace isolation — the sample used that root access to write a `@reboot` persistence entry into **both the root and invoking-user crontabs**. This is a genuine, documented Linux malware persistence technique. It was caught, contained (both crontabs cleared), and a full sweep of other persistence vectors (`/etc/cron.d`, systemd user/system units, `.bashrc`/`.profile`, `authorized_keys`, `/etc/rc.local`) came back clean.
- **Harness fix, motivated directly by this incident**: `run_sample.sh` now drops the sample to the unprivileged `nobody` user (via `setpriv`, clearing all inheritable capabilities and setting `no-new-privs`) immediately before execution — root is used only to construct the isolated network namespace. Re-running under the fixed harness produced no further persistence attempts.
- **What EDDMC's actual detection mechanism achieved against this sample: nothing measurable.** The process (both unconfigured, and with a `--bench=1M` argument) exited within roughly one second every time it was run, too short-lived to produce any eBPF-observable behavioural signal. **The XMRig identification above came entirely from manual static analysis (`strings`), not from EDDMC.** This is an honest, important distinction: this evaluation has a real, identified, real-world malware sample, but **zero confirmed EDDMC detections against unmodified in-the-wild malware** — every positive detection in this report came from either the official XMRig binary run directly, or controlled/self-authored test harnesses.

---

## 5. Network pool-hits — the "0/3" that isn't what it looks like

The official 3-trial run in session 2 shows this track failing 0/3. Read alongside §6.2's finding, that number is misleading in isolation:

- The exact same mechanism scored **50/MEDIUM/THROTTLE at t=14.0s**, correctly, in **two separate isolated demonstrations** — once immediately after the reliability bug (§6) was fixed, and once again during targeted debugging.
- **Root cause of the 3 official-trial failures**: scan-cycle latency inflation (§6.2) — the official trials happened to run shortly after XMRig-family tracks, which is precisely the adverse condition that causes it.
- `net_collector`'s eBPF-level counting was correct in every single failing trial (`mining_pool_hits` climbed 1→12 exactly as expected) — only the detection engine's scan cadence was affected, not the underlying telemetry.

**Recommended framing**: report the raw 0/3 figure transparently, immediately followed by the latency explanation and the two successful isolated demonstrations. Do not silently exclude the failures, and do not report the successes without the failures — both are real, both are explained.

---

## 6. Reliability bugs found and fixed during this evaluation

### 6.1 Detection-engine thread death (silent, permanent)
**Symptom**: detection appeared to silently stop working entirely (0/NONE for everything) while the daemon looked completely healthy — collectors running, IPC responsive, uptime normal.
**Root cause**: `DetectionEngine._loop()` called `_scan()` with no exception handling, and the end-of-scan cleanup step (`on_process_gone()`, which revokes mitigations for exited PIDs) was also unguarded at two call sites. An exception during cleanup of a forcibly-killed, previously-mitigated process would propagate up and kill the detection thread **permanently**, with no error surfaced anywhere.
**Fix**: wrapped both in try/except + `logger.exception`, matching the existing defensive pattern already used around the per-PID scoring loop.
**Verification**: after the fix, both previously-silent tracks (pool-hits, browser-WASM) scored correctly.

### 6.2 Detection-latency inflation under sustained eBPF event load
**Method**: root-caused via a `--log-level DEBUG` daemon restart and direct comparison of `[DETECT]` log timestamps for a still-alive throttled miner.
**Finding**: real scan-cycle gaps of **13.2-34.1 seconds (mean 20.2s)** against the configured 5-second `scan_interval` — a **4-7x inflation** — occurring specifically while a high-event-volume process (an active, even-throttled miner) is concurrently tracked.
**Mechanism**: `DetectionEngine._scan()` runs in one Python thread sharing the GIL with four eBPF collector threads (`syscall_collector`, `sched_collector`, `net_collector`, `mem_collector`), each calling BCC's `perf_buffer_poll()`. Under heavy event volume (BCC's own `"Possibly lost N samples"` perf-ring-buffer-overflow warnings were independently observed during this evaluation, confirming real event-processing pressure), the detection thread is starved of GIL/lock time.
**Practical consequence**: a short-lived process (~24s, like the pool-hits test client) can fall entirely inside one inflated scan gap and never be examined — a genuine, quantified, GIL-bound architectural limitation, not a scoring-logic defect. Recommended future work: move eBPF collectors to separate processes, or give the detection thread elevated scheduling priority.

### 6.3 Scratchpad heuristic false positives (prior session, already fixed and verified)
**Symptom**: 5 distinct real, legitimate processes on the test machine were detected and (with live mitigation active) actually throttled: Claude Code CLI, VS Code, this project's own Electron client-app, **`fwupd`** (standard Linux firmware-update daemon — not a browser or dev tool), and `gjs`.
**Root cause**: the memory scratchpad heuristic flagged *any* anonymous `mmap()` that was an exact multiple of 2,097,152 bytes — coincidentally also the standard Linux transparent-huge-page size, so any software aligning large allocations to huge-page boundaries (a common, unrelated performance optimisation) triggered it.
**Fix**: added a joint counter (`scratchpad_huge_allocs`) that only increments when a `mmap()` is *both* an exact 2MB multiple *and* flagged `MAP_HUGETLB` in the same call — the strong weight and hard-evidence floor now require this joint signal; a bare size match alone is scored much lower and is not floor-eligible.
**Verification**: `fwupd`'s exact observed profile dropped from MEDIUM/THROTTLE to 29/LOW (no longer mitigated) after the fix, without adding `fwupd` to any exemption list; real XMRig's exact profile still reached HIGH/BLOCK (score 78) with all real signals combined — the fix did not weaken true-positive sensitivity.

---

## 7. Detector overhead

| Condition | CPU% (mean / peak) | RSS (mean / peak) | Ambient tracked processes |
|---|---|---|---|
| Idle baseline | 172.2% / 191.7% | 88.7MB / 88.8MB | mean 1912 |
| Under active detection load (concurrent XMRig `--bench`) | 112.4% / 160.4% | 81.2MB / 88.8MB | mean 1916 |

**Important caveat**: this evaluation ran on a shared, actively-used development VM, not an isolated benchmark rig. The "loaded" figure came out *lower* than "idle" despite near-identical ambient tracked-process counts between the two runs — meaning the observed variance is dominated by ambient system noise, not by the deliberately-added test workload. **Report both numbers as independent data points, not as a controlled A/B comparison**, unless re-measured on a quiet, dedicated machine with multiple repeated trials.

---

## 8. Estimated real-world detection coverage (author's assessed opinion, not a measured statistic)

This evaluation's sample size (9 exercised scenarios across two sessions) is far too small to support a statistically valid real-world detection percentage. The following is an explicitly qualitative, scope-differentiated estimate for discussion in the thesis — not a claimed measurement.

| Scope | Estimated confidence | Reasoning |
|---|---|---|
| Standard XMRig/RandomX, bare Linux host process | ~90% | Directly proven across both sessions; multiple independent runs all converged on MEDIUM/THROTTLE |
| Same, evading via renaming/packing/thread-reduction/process-splitting | ~85% | All four angles directly tested and held up (§3) |
| CryptoNight-family (older/forked algorithms) | ~75% | Not separately tested, but the scratchpad heuristic *originates* from CryptoNight's structure — should transfer, unverified |
| Containerised/Kubernetes-targeted deployment (arguably the dominant real-world Linux cryptojacking vector — Kinsing, TeamTNT) | ~50-60% | **Never tested.** eBPF tracepoints are host-wide in principle, but no direct evidence covering container/cgroup namespace interaction |
| Sophisticated evasion (shared pre-warmed RandomX dataset, no-huge-page scratchpad, anti-sandbox detection) | ~40-50% | These specifically target the exact signals proven strongest in this evaluation |
| Unmodified, real, in-the-wild malware sample | **No measured evidence either way** | The one real sample tested never sustained execution long enough to produce a signal (§4) |
| **Blended estimate, Linux CPU cryptojacking as a whole** | **~65-70%** | Weighted down specifically by the untested container/cloud vector and the complete absence of a confirmed real-malware detection |
| Non-Linux (Windows, GPU-algorithm-based) | Out of scope by design | No Windows agent; scratchpad heuristic is RandomX/CryptoNight-specific, would not fire on GPU-targeted algorithms (Ethash, KawPow, Equihash) |

### Why this shouldn't be compared directly to published papers' 90-99% figures

Published cryptojacking-detection papers (e.g. classifier-based web-crawl studies) commonly report accuracy in the high 90s%, but this is largely a function of methodology, not a stronger detector:
1. **Measured against non-adversarial corpora** — most papers evaluate against a labelled dataset that was never specifically constructed to evade *that* detector, whereas this evaluation actively tried four distinct evasion strategies and measured detection under those conditions.
2. **Train/test distribution overlap** in ML-classifier papers can inflate apparent accuracy without proving generalisation to genuinely novel samples.
3. **Different threat models** — a web-crawl classifier ("does this page run mining JS") is a narrower, more structured problem than "does this arbitrary Linux process exhibit RandomX behaviour."
4. Most published work does not disclose untested scope gaps (e.g. containerised deployment, real-malware validation) with the explicitness applied here.

**Recommended thesis framing**: state the narrow, well-supported figure (~85-90% for the specific proven scope: bare-host Linux XMRig/RandomX, including its evasion variants) alongside explicit, named gaps (containers, real-sample validation), rather than a single blended percentage. Position the *methodology* — active multi-strategy evasion testing plus honest gap disclosure — as a discussion point distinguishing this evaluation from typical published accuracy claims.

---

## 9. Scope boundaries (explicitly out of scope, not gaps)

- **Windows-only attack vectors** (fileless PowerShell cryptojacking — Purple Fox, LemonDuck, Tor2Mine): EDDMC has no Windows agent.
- **HPC-based (MineSweeper-style) detection** and **a live Falco comparison**: not implemented/attempted in this harness — cite as related work, not as a tested baseline.
- **GPU-targeted mining algorithms** (Ethash, KawPow, Equihash): the scratchpad/huge-page heuristic is specific to RandomX/CryptoNight-family CPU mining by design.

---

## 10. Quick-reference table for the results chapter

| Metric | Value |
|---|---|
| Distinct scenarios exercised against EDDMC's eBPF mechanism | 9 |
| Detected at least once (counting isolated demonstrations where disclosed) | 9/9 |
| Mitigated with real cgroup enforcement at least once | 8/9 |
| False positives across all benign baselines | 0 |
| Evasion strategies tested | 4 (renaming, packing, thread-reduction, process-splitting) |
| Evasion strategies that succeeded | 0 |
| Real-world malware samples fetched | 5 (1 Windows PE, 4 ELF) |
| Real-world malware samples architecture-compatible with test VM | 1 |
| Real-world malware samples confirmed identified (static analysis) | 1 |
| Real-world malware samples with confirmed EDDMC eBPF detection | 0 |
| Real security incidents encountered and contained | 1 (crontab persistence, both root and user, both cleared) |
| Reliability bugs found and fixed | 2 (thread-death, scan-latency) + 1 from prior session (scratchpad FP heuristic) |
| Estimated confidence — proven scope (Linux XMRig/RandomX + evasion variants) | ~85-90% (author's assessed estimate, not measured) |
| Estimated confidence — Linux cryptojacking overall | ~65-70% (author's assessed estimate, not measured) |
