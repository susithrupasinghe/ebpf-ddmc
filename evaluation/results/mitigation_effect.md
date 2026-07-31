# Mitigation effect: real CPU% before vs. after THROTTLE (Chapter 6 data extraction, Task 7)

## Result

**Mean CPU utilisation dropped from 99.7% to 30.0% (a 69.9-percentage-point / 70% reduction) the moment THROTTLE engaged**, measured independently of the daemon (`evaluation/measure_mitigation_effect_v2.py`, real `psutil.Process(pid).cpu_percent(interval=None)` sampled every 1s from outside the daemon entirely), against a daemon run with real mitigation enforcement (`mitigation.dry_run: false`).

| Window (daemon's own tier at that tick) | n ticks | mean CPU% | min | max |
|---|---|---|---|---|
| Pre-detection (mitigation=NONE) | 10 | 99.7% | 98.0% | 100.8% |
| LOW / ALERT (logged only, no enforcement) | 12 | 100.1% | 99.7% | 100.8% |
| MEDIUM / THROTTLE, settled (excl. first transitional tick) | 67 | 30.0% | 28.9% | 30.9% |

THROTTLE first applied at t=23.1s (pid=33300, comm=xmrig, real XMRig `--bench=1M --randomx-mode=light -t 1`). The single tick at the THROTTLE transition itself (75.7%) is excluded from the "settled" row above as a cgroup-quota ramp-in artefact and reported separately below; including it, THROTTLE's mean is 30.7% over n=68.

Source: `evaluation/results/mitigation_effect_v2.csv`.

## Why this took two attempts, and what the first attempt actually found

The first attempt (`evaluation/build_mitigation_effect.py`, `task7_mitigation_effect.csv`, preserved for reference) tried exposing the scorer's own internal `cpu_percent` value directly in the capture schema (`daemon/detector/engine.py` now persists `fp.parallelism.cpu_percent` into the process store each tick — this change is real and stays; `evaluation/results_capture.py` records it). That attempt came back with `cpu_percent` empty for every pre-detection tick and could not establish a before/after comparison.

**Root cause, since confirmed** (temporary diagnostic logging added to `engine.py`, verified, then reverted — no trace left in the codebase): this was not a bug in the new `cpu_percent` field. Direct evidence from a fresh capture with 1s external polling:

| elapsed_s | total_syscalls (eBPF collector output) | score (scorer output) | cpu_percent (scorer output) |
|---|---|---|---|
| 0–9 | 843 → 920 (climbing every tick) | 0.0 (flat) | empty (flat) |
| 10–15 | 923 → 938 (still climbing every tick) | 26.0 (flat) | '0.0' (flat) |

The eBPF **collectors** run every ~1 second as expected. The **scorer's** `_scan()` cycle — where `score`, `confidence`, `mitigation`, and (this round) `cpu_percent` are all set together, in the same block, every tick — runs far less often. This is not a new defect: it is the **same scan-cycle-latency problem already quantified in `evaluation/results/REPORT.md` §4** (mean 20.2s, max 34.1s gaps between real `_scan()` invocations under eBPF event load), now visible in a new field because `cpu_percent` didn't exist in the capture schema when that defect was first characterised. A 1-second poll interval was always going to see many repeated/stale reads between real scans; the first attempt's "23 THROTTLE-tier ticks, min=max=92.6%" was never 23 independent samples, it was however many *real* scan cycles happened to touch that PID, each repeated across several polls.

**Fix applied for this measurement, not to detection logic**: sample CPU utilisation independently of the daemon's scan cadence entirely (`measure_mitigation_effect_v2.py`, plain `psutil` in a standalone script), and use the daemon's own `/api/processes` only for its current confidence/mitigation tier as a boundary marker. This sidesteps the scan-cycle-latency defect for measurement purposes without touching `engine.py`'s detection logic (which remains as committed for Task 7's original, still-valid schema-exposure change).

## A second thing this surfaced: dry-run was on

The first real run under this fix still showed **no CPU drop at all** after THROTTLE (flat ~99–100% throughout). This was not a mitigation-effectiveness failure: `daemon/config/local.yaml` has `mitigation.dry_run: true` (a deliberate development-safety default in this environment — the same file allowlists this machine's VS Code and Claude Code binaries). Under dry-run, THROTTLE is logged (`[DRY-RUN] Would apply THROTTLE to pid=...`) but no cgroup quota is ever applied. The real 30.0% figure above was obtained by restarting the daemon with a small config layered on top via `--config` (`mitigation: {dry_run: false}` only — `local.yaml` itself was not edited, and config load order is `defaults → local.yaml → --config`, so every other setting, including the allowlist, was unchanged), with the user's explicit confirmation before enabling real enforcement on the live host.

## Caveat

`cpu_percent` (the scorer's own internal field, exposed this round) still uses psutil's `Process.cpu_percent(interval=None)` convention and still only updates once per real scan cycle — that part of the original Task 7 ask (expose the scorer's internal value in the capture schema) is done and committed, and remains useful for anything that doesn't need faster-than-scan-cadence resolution. The 70% figure above comes from the *independent* sampling script, not from that field, for the reasons above.
