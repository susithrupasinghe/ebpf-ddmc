# Final Evaluation Report (RO2 / RO4 / RO6 / RO7 closure)

Generated from every file in `evaluation/results/final/` (16 files present at report time).

Figure: `evaluation/figures/fig_cascade_progression.png` (score vs. time, tier boundaries, enforcement-action markers).

## 1. Platform and artefact version

- `platform.json`: kernel=7.0.0-28-generic arch=aarch64 cores=4 mem=3.3GB git_sha=f275788b4f7c dirty=True

## 2. Objective status

| RO | Status | Evidence |
|---|---|---|
| RO2 (lightweight daemon) | Partially met | no overhead run recorded this round |
| RO4 (policy-driven mitigation) | Met -- 3 trial(s), all reached CRITICAL with real cgroup+iptables+SIGSTOP enforcement (verified in kernel state, not the daemon log), reversibility confirmed via revoke | ['cascade_trial1_summary_20260802T005910.json', 'cascade_trial2_summary_20260802T010533.json', 'cascade_trial3_summary_20260802T011057.json'] |
| RO6 (evaluate across 5 dimensions) | Partially met | overhead: False, baseline: True |
| RO7 (fingerprint registry) | Partially met -- gate correctly rejects recalibration (poisoning-resistance check failed); futex_ratio condition remains a real calibration mismatch for RandomX, unresolved this round | ['registry_gate_replay_20260802T011128.json'] |

## 3. Cascade results

### Trial 1

- Peak score: 100.0 / CRITICAL
- Stratum: connections=1 jobs_sent=1 submits=0
- Events: [[73.99398040771484, 'first CRITICAL, score=84.0'], [73.99398040771484, 'revoke called, cgroup_removed=True, proc_resumed=True']]
- cgroup quota at end: exists=False value=None
- Process state at end: S
- Reversibility (revoke called at t=74.0s): cgroup quota existed before=True, removed after=True; iptables block existed before=True, removed after=True; process resumed=True (state after: S)

### Trial 2

- Peak score: 100.0 / CRITICAL
- Stratum: connections=1 jobs_sent=1 submits=0
- Events: [[58.870566606521606, 'first CRITICAL, score=84.0'], [58.870566606521606, 'revoke called, cgroup_removed=True, proc_resumed=True']]
- cgroup quota at end: exists=False value=None
- Process state at end: S
- Reversibility (revoke called at t=58.9s): cgroup quota existed before=True, removed after=True; iptables block existed before=True, removed after=True; process resumed=True (state after: S)

### Trial 3

- Peak score: 100.0 / CRITICAL
- Stratum: connections=1 jobs_sent=1 submits=0
- Events: [[81.78894901275635, 'first CRITICAL, score=84.0'], [81.78894901275635, 'revoke called, cgroup_removed=True, proc_resumed=True']]
- cgroup quota at end: exists=False value=None
- Process state at end: S
- Reversibility (revoke called at t=81.8s): cgroup quota existed before=True, removed after=True; iptables block existed before=True, removed after=True; process resumed=True (state after: S)

**Finding worth flagging**: across all trials, once `revoke` lifted real cgroup/iptables/SIGSTOP enforcement, kernel state stayed clear for the remainder of the run -- but the daemon's own displayed `mitigation` column kept reading `CRITICAL`/`TERMINATE` the whole time (the underlying xmrig process resumed identical behaviour after SIGCONT, so the *score* never dropped; and since CRITICAL is the top tier, the engine's tier-escalation check -- which only re-fires `_on_mitigation()` when the tier strictly increases -- has nowhere higher to escalate to, so it never re-applies at the same tier). Reversibility of the **enforcement actions** is real and durable; the **status display** does not reflect a revoked-but-still-scored-CRITICAL process, which is a genuine observability gap worth a mention in the dissertation's limitations, separate from whether reversibility itself works (it does).

## 4. Fingerprint confirmation gate

- Original gate: {'sustained_critical_60s': True, 'pool_connection': True, 'futex_ratio_0.40': False, 'cpu_bound_ratio_0.92': True, 'thread_cpu_ratio_1.0': True}
- Recalibrated gate: {'futex_ratio': 0.051, 'cpu_bound_ratio': 0.92, 'thread_cpu_ratio': 1.0}
- Poisoning check: {'benign_total': 5097, 'benign_pass_original': 0, 'benign_pass_recalibrated': 30}
- Recalibration accepted: False

## 5. Two-node time-to-detection

Not performed this round.

## 6. Runtime overhead

Not performed this round (see quietness-check file if present).

## 7. Baseline comparison

- Signal validation: {'xmrig_postfix.csv (post-fix)': {'n': 296, 'mean': 53.12522194568451, 'max': 308.7982724615385}, 'xmrig_ground_truth_1M.csv (pre-fix, for reference only)': {'n': 285, 'mean': 0.009994219257428938, 'max': 0.12933804878048777}}
### B1_cpu_threshold

- Reading 1 best: T=80 D=10 F1=1.000 recall=1.000 precision=1.000 FP=0 fp_by_track={}
- Reading 3 best: T=60 D=10 F1=0.800 recall=0.667 precision=1.000 FP=0 fp_by_track={}

### B2_cpu_thread

- Reading 1 best: T=60 D=10 F1=0.800 recall=0.667 precision=1.000 FP=0 fp_by_track={}
- Reading 3 best: T=60 D=10 F1=0.500 recall=0.333 precision=1.000 FP=0 fp_by_track={}

### B3_cpu_io

- Reading 1 best: T=60 D=10 F1=nan recall=0.000 precision=nan FP=0 fp_by_track={}
- Reading 3 best: T=60 D=10 F1=nan recall=0.000 precision=nan FP=0 fp_by_track={}


## 8. Not attempted / inconclusive / failed

- **Task A5 (two-node experiment): skipped**, per the task's own instruction ("if any benign observation passes the recalibrated gate, the recalibration is rejected... do not proceed to A5"). A4's poisoning-resistance check rejected the recalibrated gate (30/5097 benign observations would have passed it), so A5 was correctly not run this round.

- **Task B (runtime overhead): not performed this round.** This host's ambient CPU noise (a shared, actively-used development VM) exceeded the ~20%-of-one-core quietness gate at the time of checking. Awaiting a quiet reboot before attempting.

- **Baseline comparison (Task C): only 4 of 7 original tracks recaptured** under the fixed collector (xmrig_ground_truth via the postfix-verification round, evasion_throttled, packed_xmrig, plus 2 benign tracks). `network_pool_blocklist` and `browser_wasm_miner` were not recaptured this round -- excluded from the sweep, not padded with stale pre-fix data. The pre-fix tracks in `evaluation/results/` remain structurally unusable for this signal (see the baseline sweep's own validation output) and were not substituted in.

- **RO7's futex_ratio calibration gap remains unresolved.** The original gate's futex_ratio>=0.40 condition cannot pass for RandomX by design (workers hash, they don't synchronise -- observed max across all mining captures this round: 0.0485). The one recalibration attempt tried this round was rejected by the poisoning-resistance check. No further recalibration attempt was made -- reported as an open gap rather than force-fitting a second attempt.

