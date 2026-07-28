# EDDMC — Evaluation Work Order (pre-Chapter 6)

**Purpose of this document.** This is a task brief for Claude Code working in the EDDMC
repository. A review of `FINAL_EVALUATION_SUMMARY.md` against the MSc thesis
(`EDDMC_Thesis_Interim_Report_W2121694.docx`) found that the current evaluation data
cannot yet support Chapter 6 as the thesis is written. This document lists what needs to
be run, measured, fixed, or explicitly abandoned, in priority order, with acceptance
criteria for each.

**Thesis context you need to hold.** EDDMC is an eBPF-based daemon for detecting and
mitigating CPU cryptojacking on Linux, using deterministic weighted scoring (explicitly
*not* machine learning) over eight kernel-derived behavioural features, with a five-tier
mitigation cascade (NONE / LOW / MEDIUM / HIGH / CRITICAL) and an optional Distributed
Behavioural Fingerprint Registry. The chapter must answer six research questions:

| RQ | Question | Current evidence status |
|---|---|---|
| RQ1 | Which kernel-level features distinguish mining from benign high-compute work? | Partial — needs per-feature separation analysis |
| RQ2 | Can eBPF capture those signals with sufficient fidelity? | Adequate, but undocumented features exist |
| RQ3 | Does deterministic scoring detect reliably under evasion? | Strong |
| RQ4 | What runtime overhead does the daemon introduce? | **Unusable — must re-measure** |
| RQ5 | How effective is policy-driven mitigation? | Partial — enforcement applied but effect unmeasured |
| RQ6 | Does the fingerprint registry accelerate cross-deployment detection? | **No data at all** |

## Ground rules

1. **Never invent a number.** Every figure must trace to a CSV, a log line, or a
   reproducible command. If something cannot be measured in the time available, say so
   explicitly and it will be written up as a limitation. A documented gap is worth more
   than a fabricated result and costs far less in a viva.
2. **Do not silently drop failing trials.** If a track fails 0/3, that gets reported as
   0/3. The existing summary's honesty about the pool-hits failures is a strength, not a
   defect — preserve that standard.
3. **Record the artefact version (git SHA) for every run.** Results gathered before and
   after a bug fix are not poolable, and the chapter will present them as separate design
   iterations.
4. **Emit machine-readable output.** Every task below should produce a CSV or JSON in
   `evaluation/results/` alongside any human summary, so tables can be regenerated.

---

## P0 — Blocking. Chapter 6 cannot be written without these.

### P0-1. Fingerprint registry: produce evidence, or formally cut the claim

**Problem.** The registry is positioned in the thesis as the headline novel contribution
(§1.5, §1.6.1, §1.6.2, Objective 7, RQ6). No evaluation data exists for it. Worse, it is
structurally unreachable: the confirmation gate in `daemon/fingerprint/assessor.py`
requires CRITICAL tier (score ≥ 80) sustained for 60 continuous seconds, and every
observed XMRig run peaks at **45–46 (MEDIUM)**. The gate can never fire, so nothing is
ever submitted, so the matcher has nothing to match.

**Investigate first, before changing anything:**

- Confirm the gate has genuinely never fired. Grep daemon logs for confirmation-gate
  evaluations and submission attempts. Report how many times each of the four gate
  conditions passed individually.
- Establish *why* scores cap at 45–46. Instrument the scorer to dump per-feature
  contributions for a live XMRig process and report the breakdown. The working hypothesis
  is that `pool_hits` — one of the three highest-weighted features — is structurally zero
  because all runs used `--bench` mode, which performs no pool connection. Confirm or
  refute this with data.

**Then choose one of three paths and report which, with the evidence behind it:**

- **Path A (preferred, if the hypothesis holds).** Run XMRig against a *local mock stratum
  listener* so `pool_hits` is non-zero, and re-measure peak score. If scores then reach
  HIGH or CRITICAL, the tier cascade is vindicated and the registry becomes reachable.
  Proceed to the two-node experiment below.
- **Path B.** If scores still cannot reach CRITICAL under realistic conditions, the gate
  threshold is mis-calibrated relative to the scorer. Propose a defensible recalibration
  (e.g. gate on sustained HIGH plus verified stratum connection rather than CRITICAL) and
  document the reasoning. This is a legitimate DSR refinement, not a fudge — but it must
  be argued from the observed score distribution, not chosen to make the demo work.
- **Path C.** If neither is achievable in the time available, say so plainly. The thesis
  will then reframe the registry as a designed-and-implemented but unevaluated component,
  RQ6 will be answered as "not empirically assessed," and Objective 7 will be reported as
  partially met. This is survivable if stated openly and early.

**Two-node experiment (required for Paths A or B), per thesis §3.10.6:**

- Node A: run XMRig to confirmation, verify a fingerprint reaches the registry server.
- Node B: independent EDDMC instance, no detection history. Run the same miner variant.
- Primary metric: time from process start to first HIGH-tier alert, measured **with**
  and **without** fingerprint matching enabled. Minimum 3 trials per condition; report
  mean ± SD.
- Secondary metric: run the matcher against all benign workloads and confirm cosine
  similarity does not elevate any legitimate process. Report the actual similarity scores,
  not just pass/fail.

**Acceptance criteria:** a CSV of per-trial time-to-detection for both conditions; the
matcher's similarity scores against every benign workload; a stated path (A/B/C) with
supporting evidence.

---

### P0-2. Re-measure daemon overhead properly

**Problem.** The current figures (172.2% mean CPU idle, 88.7 MB RSS, falling to 112.4%
*under load*) are unusable. Load being lower than idle proves the measurement is dominated
by ambient noise. A daemon consuming ~1.7 cores also flatly contradicts the "lightweight"
claim that runs through Chapters 1, 3, and 5 and directly fails research challenge CH4.

**What to do:**

- Re-run on a **quiet, dedicated host** with no other interactive workload. Reboot first.
  Confirm the machine is genuinely idle before starting (report 60s of baseline system-wide
  CPU before the daemon starts).
- Minimum **5 trials per condition**, each ≥ 300 seconds, reporting mean ± SD:
  1. Daemon stopped (system baseline)
  2. Daemon running, no target workload (idle overhead)
  3. Daemon running, benign high-CPU workload active
  4. Daemon running, XMRig active
- Measure daemon CPU% and RSS separately from system-wide CPU%. Make clear whether CPU%
  is normalised per-core or aggregate across 4 cores — the current 172% figure is
  ambiguous and that ambiguity is itself part of the problem.
- Report the marginal overhead (condition 2 minus condition 1), which is the number the
  thesis actually needs.

**Also investigate:** the summary reports a mean of ~1912 ambient tracked processes.
Confirm whether the daemon is genuinely scoring ~1900 processes every scan cycle. If so,
that is very likely the root cause of both the overhead figure and the scan-latency
inflation in §6.2, and the process filter needs examining. Report what the filter actually
admits.

**Acceptance criteria:** CSV with per-trial CPU% and RSS across all four conditions; an
explicit statement of the normalisation convention; a finding on the process-filter scope.

---

### P0-3. Resolve the platform contradiction

**Problem.** The thesis (§3.8, §5.2.3) specifies a Contabo cloud VPS, Ubuntu 24.04, Linux
6.x, 4 vCPU, 12 GB RAM. The evaluation ran on `aarch64` with kernel `7.0.0-27-generic` on
a "shared, actively-used development VM." Three consequences: the architecture mismatch is
why 3 of 4 ELF malware samples were unrunnable; RandomX huge-page behaviour is
architecture-sensitive, so results may not transfer to the stated x86-64 cloud target; and
Chapter 5 currently documents an environment that was never evaluated on.

**Preferred fix:** re-run the full evaluation suite on the x86-64 Contabo VPS described in
the thesis. This also resolves P0-2 (dedicated quiet host) and improves the malware-sample
architecture match at the same time — likely two of the three previously-unrunnable ELF
samples become testable.

**Fallback:** if the VPS is unavailable, capture exact platform facts (`uname -a`,
`lscpu`, `/etc/os-release`, kernel config relevant to eBPF/BTF) so Chapter 5 can be
rewritten accurately, and flag architecture generalisability as an explicit limitation.

**Acceptance criteria:** a `platform.json` capturing full environment facts for whichever
host is used, generated automatically at the start of every evaluation run from now on.

---

### P0-4. Reconcile the implemented feature set with Chapter 5

**Problem.** Thesis §5.5.2 documents eight features: `futex_ratio`, `io_ratio`,
`cpu_bound_ratio`, `thread_density`, `mmap_ratio`, `nanosleep_ratio`, `pool_hits`,
`cpu_percent`. The evaluation references `scratchpad_floor`, `scratchpad_huge_allocs`,
`thread_full_sat`, and a `MAP_HUGETLB` joint counter — none of which appear in the thesis.
Thesis §5.5.1 describes three eBPF C programs; the evaluation shows four collectors
(`mem_collector` is undocumented). Chapter 6 cannot report on features Chapter 5 never
introduces.

**What to do:** produce an authoritative inventory of the artefact as it currently exists:

- Every feature the scorer consumes: name, source collector, normalisation, default
  weight, and whether it is hard-evidence-floor eligible.
- Every eBPF program: file, attach point (tracepoint vs kprobe), and what it populates.
- Every tier boundary and every mitigation action, as actually implemented — the thesis
  Table 2 says MEDIUM applies a 30% cgroup throttle and HIGH adds a network block; confirm
  this matches the code.
- Any divergence from the thesis, listed explicitly so Chapter 5 can be corrected.

**Acceptance criteria:** `docs/ARTEFACT_INVENTORY.md` with the above, plus a short
"divergences from thesis Chapter 5" section.

---

## P1 — Needed for a credible chapter, but not blocking.

### P1-1. Compute a real confusion matrix

Thesis §3.10.1 promises true positives, false positives, false negatives, detection rate
and miss rate. A scenario tally is not that, and the gap analysis explicitly benchmarks
against CryptoGuard's F1 > 96% — so precision, recall, and F1 will be expected.

- Define the unit of classification explicitly and defend it. Recommended:
  **per-process-per-scan-cycle observation**, with a process counted positive at MEDIUM
  or above.
- Build the matrix from the existing per-poll CSVs in `evaluation/results/` if they retain
  per-observation granularity. Report whether they do; if not, re-run capture with
  per-observation logging.
- Report precision, recall, F1, and false-positive rate, with the observation count (n)
  stated so the reader can judge the sample size.
- Report separately for pre-fix and post-fix artefact versions. Do not pool them.

### P1-2. Measure mitigation *effect*, not just mitigation *application*

Current evidence proves a cgroup quota was written to `/sys/fs/cgroup/eddmc/<pid>/cpu.max`.
It does not show the throttle worked. Thesis §3.10.4 asks for time-to-action and response
success rate.

- For each mitigation event, record: time from tier crossing to enforcement applied
  (time-to-action, distinct from time-to-alert); the target process's CPU% for 30s before
  and 60s after enforcement; and for XMRig specifically, hashrate before and after if the
  benchmark reports it.
- Verify reversibility as the thesis claims (§5.5.4): drive a process's score back below a
  boundary and confirm the cgroup quota and iptables rules are actually removed.
- Confirm whether HIGH-tier network blocking and CRITICAL-tier SIGSTOP/SIGKILL have *ever*
  been exercised against a real process. The summary suggests only THROTTLE was, apart
  from one incidental mention of score 78 / HIGH / BLOCK in §6.3. If the upper cascade is
  untested, RQ5 can only be partially answered — establish which it is.

### P1-3. Broaden benign workload coverage

The "zero false positives" claim currently rests on two workload types (OpenSSL `speed`,
`gcc`). The thesis commits to gcc, nginx, ffmpeg, and PostgreSQL/pgbench (§3.9, §5.3).
Since low false-positive behaviour is a central differentiator against ML baselines, two
workloads is thin.

- Add ffmpeg transcoding, PostgreSQL under pgbench, and nginx under load.
- Run each ≥ 3 trials, ≥ 5 minutes, recording peak score and tier.
- Also re-run `fwupd` and the other four processes from the §6.3 false-positive incident,
  to confirm the huge-page fix holds under the current build.

### P1-4. Add the missing miner variants

Thesis §5.3 commits to three XMRig configurations including `--cpu-max-threads-hint` at
~50%, plus `cpuminer-multi` as a second miner family to demonstrate the detector is not
overfitted to XMRig. Neither appears in the evaluation.

- Run XMRig with `--cpu-max-threads-hint=50` as specified.
- Run `cpuminer-multi`. Note in advance that it uses CryptoNight-family rather than
  RandomX, so the scratchpad heuristic may behave differently — whatever the result, it is
  a genuine finding about generalisation across mining algorithms and directly informs the
  ~75% CryptoNight-family estimate in §8.

### P1-5. Report time-to-alert against the design target

Observed time-to-alert ranges 27.7–81.7s against a configured 5-second scan interval, with
§6.2 documenting real cycle gaps of 13.2–34.1s. This matters because "Early Detection" is
the first word of the system's own name.

- Report mean ± SD time-to-alert per scenario, not just ranges.
- Relate every figure to the 5s design target and the measured scan-cycle inflation.
- Re-check whether the §6.2 latency inflation persists after the P0-2 process-filter
  investigation — if the daemon is scoring 1900 processes per cycle, fixing that may
  resolve the latency finding too. If it does, that is a significant result and changes
  what Chapter 6 says about the GIL limitation.

---

## P2 — Nice to have, only if time permits.

- **Re-test the MalwareBazaar samples on x86-64.** If P0-3 moves evaluation to the Contabo
  VPS, at least two previously-unrunnable ELF samples become testable. A single confirmed
  eBPF detection against genuine in-the-wild malware would materially strengthen the
  chapter — currently that count is zero.
- **Investigate why the aarch64 sample died in ~1 second.** Missing library, architecture
  mismatch, sandbox restriction, or anti-analysis check? A one-line root cause is worth
  having even if the sample stays undetected.
- **Container-scoped test.** §8 flags containerised deployment (the dominant real-world
  Linux cryptojacking vector — Kinsing, TeamTNT) as never tested, at 50–60% estimated
  confidence. Even a single Docker-hosted XMRig run, detected or not, converts a pure
  speculation into a data point.
- **Qualitative capability comparison table** against CryptoGuard (Park et al., 2025), Kim
  et al. (2025), and Karn et al. (2021), across: training-data requirement, explainability,
  mitigation integration, deployment model, cross-host intelligence. Capability-level only
  — do **not** fabricate head-to-head performance numbers against systems that were never
  reimplemented or run here.

---

## Explicitly do NOT do

- Do not tune thresholds to make a specific test pass and then report that test as
  independent validation. If thresholds change, everything must be re-run and the change
  documented as a design iteration.
- Do not merge the two evaluation sessions into one tally. They ran against different
  artefact versions, across the thread-death fix, the scratchpad fix, and the latency
  finding.
- Do not report the "9/9 detected" headline. It counts isolated demonstrations for a track
  that failed 0/3 officially, and counts a browser-WASM run that also produced NONE. Report
  official trials, then disclose the isolated demonstrations separately with the latency
  explanation.
- Do not produce estimated real-world coverage percentages (the ~65–70% figure). The
  scope-differentiated reasoning is valuable, the numbers are not defensible, and they will
  invite a question in the viva that has no good answer.

---

## Deliverables back

1. `evaluation/results/*.csv` — regenerated, with `platform.json` and git SHA per run.
2. `docs/ARTEFACT_INVENTORY.md` — P0-4.
3. `reports/EVALUATION_ROUND2.md` — updated summary in the same honest style as
   `FINAL_EVALUATION_SUMMARY.md`, with a clear statement per task of: completed / partially
   completed / not attempted, and why.
4. A short **status note on P0-1** specifically — which path (A/B/C) the registry evidence
   supports. This single answer determines whether RQ6 can be answered at all, and
   therefore how Chapter 6 and the thesis's central novelty claim must be framed.