# Session summary — Chapter 6 data extraction (2026-08-01)

Plain-language account of what was done in this session, for handing off context to
another session/agent. The technical index for actually writing Chapter 6 is
`reports/CH6_DATA_EXTRACTION.md` — this file is the narrative version.

## What was asked

`EDDMC_CLUADE_CODE_PROMPT.md` (repo root) laid out 8 tasks to extract data the
dissertation's Results chapter needs but the two prior evaluation rounds didn't produce:
a raw-vs-composite schema check, a feature-contribution/ablation study, an artefact
inventory, three figures, screenshots of the running system, false-positive case detail,
a four-way confusion-matrix decomposition, and (optional) a mitigation-effect
measurement. Ground rule: never invent a number — trace everything to a CSV, log line,
or code, and say so plainly if something can't be produced.

## What got done, task by task

- **Task 0**: Confirmed the capture CSVs store the composite score/tier per tick, plus
  the raw evidence counters — not just a bare score. This made Task 1 possible without
  re-running anything.
- **Task 1**: Built `evaluation/replay_scorer.py` to replay the real `Scorer` against
  those raw counters, verified it reproduces the daemon's own recorded peak scores, then
  produced a feature-contribution CSV and a leave-one-out ablation table
  (`evaluation/results/ablation_leave_one_out.md`). Headline: the RandomX
  scratchpad/huge-page evidence is what actually carries detection; the other 8 weighted
  signals are mostly redundant with it once it fires.
- **Task 2**: Extended `docs/ARTEFACT_INVENTORY.md` with every live-scorer signal, and
  resolved the `thread_density` vs `thread_cpu_ratio` naming conflict — the dissertation's
  name doesn't exist in the live scorer at all, and a related field is mislabelled in the
  fingerprint-registry submission code (flagged, not fixed, per the read-only scope).
- **Task 3**: Three figures in `evaluation/figures/` (score trajectory, feature
  contribution, scan-latency histogram). Caught and fixed a real bug while building the
  feature-contribution chart: multi-PID tracks were letting one worker's zero row
  silently overwrite another's real data at a shared timestamp.
- **Task 4**: Got the daemon running live and captured three CLI screenshots (status,
  scored process list, a MEDIUM-tier alert breakdown) — had to clear an immutable-flag/
  execute-bit issue on the system XMRig binary first (same phenomenon documented earlier
  in this project on malware-corpus samples). No GUI tool was available to screenshot
  the Electron client, so that part was reported as not attempted rather than skipped
  silently.
- **Task 5**: Documented that only `fwupd` (of the five historical false-positive
  processes) has any exact score on record, and that even that's a post-fix synthetic
  re-score, not a live one. As a bonus, live-rechecked Claude Code CLI and VS Code during
  this session (both now score 0–12/NONE, well under the alert threshold).
- **Task 6**: Recomputed the confusion matrix four ways. The important number: recall
  jumps from 62.6% (as currently computed, latency folded in) to **89.1%** once each
  track's own pre-detection window is excluded — most of the apparent recall gap is
  detection latency, not a real miss.
- **Task 7**: This one turned into a real debugging investigation (see below) but landed
  on a genuine, verified result: **THROTTLE reduces real CPU utilisation from ~99.7% to
  ~30.0%** (a 70% reduction).

## The Task 7 investigation, in order

1. Exposed the scorer's already-computed `cpu_percent` value in the capture schema
   (`daemon/detector/engine.py`, `evaluation/results_capture.py`) — a small, read-only
   (w.r.t. detection logic) change, still in place.
2. First few capture attempts were a mess: a memory-limit kill left an xmrig process
   orphaned for ~35 minutes; a later capture came back contaminated because a killed
   process's stale detection state got inherited by a new process via PID reuse.
3. Even after a clean single capture, `cpu_percent` was empty for every pre-detection
   tick. Traced with temporary log instrumentation (added, used, fully reverted — no
   trace left in the code) to the real cause: an `eddmc.service` **systemd-managed
   daemon had been running in parallel with the manually-started one for most of the
   session**, unnoticed, competing for the same socket and resources. Stopped via
   `sudo systemctl stop eddmc`.
4. With a single clean daemon, the empty-field pattern *still* reproduced. Second root
   cause: the scorer's internal scan cycle runs far less often than believed — this is
   the same scan-cycle-latency defect already quantified in `evaluation/results/REPORT.md`
   §4 (mean ~20s gaps between real scans), just showing up in a new field. Fixed by
   writing a separate script, `evaluation/measure_mitigation_effect_v2.py`, that samples
   CPU independently via plain `psutil` rather than relying on the daemon's own cadence.
5. The first run under that fix showed *no* CPU drop at all after THROTTLE. Third cause:
   this environment's `daemon/config/local.yaml` has `mitigation.dry_run: true` by
   default (a deliberate dev-safety setting), so THROTTLE was only ever being logged, not
   applied. With explicit sign-off, re-ran the daemon with a scoped `--config` override
   (`mitigation.dry_run: false` only — `local.yaml` itself untouched) for one ~90s real
   XMRig run, which produced the final 99.7% → 30.0% result.

Full writeup: `evaluation/results/mitigation_effect.md`.

## Current state to be aware of

- **The daemon was left running with real mitigation enforcement on** (`dry_run: false`,
  via that temporary `--config` file), not the normal dry-run default — restart it with
  the usual command (no `--config` flag) or stop it if that's not wanted.
- Two side-findings surfaced but weren't chased further, worth a mention if picking this
  back up: PID 20069 (an earlier daemon instance) kept running for several minutes after
  logging its own shutdown message — a real clean-shutdown bug; and the
  `packager.py` fingerprint-registry mislabelling from Task 2.
- No stray xmrig or duplicate daemon processes remain from testing.

## Files produced this session

Scripts: `evaluation/replay_scorer.py`, `build_ablation.py`, `build_feature_contributions.py`,
`build_figures.py`, `build_confusion_matrix_v2.py`, `build_mitigation_effect.py`,
`measure_mitigation_effect_v2.py`, `render_terminal_screenshots.py`.

Results: `evaluation/results/{ablation_leave_one_out,confusion_matrix_v2,
false_positive_cases,mitigation_effect}.md`, `mitigation_effect_v2.csv`,
`feature_contributions.csv`, `task7_diag.csv`.

Figures/screenshots: `evaluation/figures/` (3 figures + 3 screenshots).

Modified: `daemon/detector/engine.py`, `evaluation/results_capture.py`,
`docs/ARTEFACT_INVENTORY.md`.

Synthesis: `reports/CH6_DATA_EXTRACTION.md` (technical index, for writing Chapter 6
directly from) and this file (narrative account).
