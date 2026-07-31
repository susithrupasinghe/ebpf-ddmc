# Chapter 6 data extraction — synthesis (2026-08-01)

This is the index for a follow-on data-extraction round on top of
`reports/CHAPTER_06_RESULTS.md` and `reports/EVALUATION_ROUND2.md`. Eight
tasks were scoped; all eight were attempted, and each is reported below with
what it produced, where the artefact lives, and — where relevant — what it
could *not* establish. Nothing here overwrites the two prior reports; it
supplements them with sharper reads on the same underlying capture data,
plus the round's few genuinely new live measurements.

## Task 0 — raw-vs-composite CSV schema question

`evaluation/results/*.csv` store the **composite** per-tick score (`score`,
`confidence`, `mitigation` columns) that `Scorer.score()` produced live during
capture, not a set of raw per-feature values that would need re-deriving.
The raw evidence counters (`futex`, `mmap`, `scratchpad_allocs`,
`huge_page_requests`, etc.) are also present per row, which is what made
Task 1's replay-based ablation possible without needing to re-instrument
anything.

## Task 1 — feature-contribution trace + leave-one-out ablation

- **Tooling**: `evaluation/replay_scorer.py` (loads the live `Scorer` with
  its real `defaults.yaml` weights, replays each CSV row's raw evidence
  columns back through it, and — critically — verified its replayed peak
  score matches the daemon's own originally-recorded peak score for every
  track before any ablation was trusted).
- **Feature-contribution CSV**: `evaluation/results/feature_contributions.csv`
  (per-tick, per-feature weighted contribution; feeds `fig_feature_contribution.png`).
- **Ablation table**: `evaluation/results/ablation_leave_one_out.md` — one
  weight-zeroing table and one evidence-zeroing ("floor-inclusive") table
  per track (5 tracks: XMRig ground truth, self-throttled evasion, UPX-packed,
  browser WASM miner, network pool-hits).
- **Headline finding**: for all three "pure mining" tracks, zeroing any
  single *weight* leaves detection intact (MEDIUM survives) — the scorer's
  signals are redundant with each other at the peak tick. The thing that is
  *not* redundant is the **hard evidence itself**: zeroing the underlying
  `scratchpad_huge_allocs` raw counter (not just its weight) drops XMRig
  ground truth from 45→23 (MEDIUM→LOW) and the self-throttled evasion track
  from 45→5 (MEDIUM→NONE) — i.e. the RandomX scratchpad/huge-page joint
  signature is doing the real work, and the other 8 weighted signals mostly
  correlate with it rather than adding independent evidence. The browser
  WASM miner (peak 39/LOW) is the outlier: no single feature dominates it,
  and it never reaches MEDIUM in this reading regardless of ablation —
  consistent with Reading 4 in Task 6 below.
- The network-pool-hits track's replay **deliberately disagrees** with the
  daemon's originally-recorded score (50/MEDIUM replayed vs. 0/NONE
  recorded) — this is not a bug in the replay, it is independent
  corroboration of `REPORT.md` §4's scan-cycle-latency finding: the real
  scan loop never reached this short-lived process in time, so the
  eBPF-collected raw evidence was there but never scored live.

## Task 2 — artefact inventory + `thread_density`/`thread_cpu_ratio` conflict

- **`docs/ARTEFACT_INVENTORY.md`** (regenerated/extended this round) — full
  per-feature table of the 14 weighted signals the live scorer actually
  consumes (`Scorer.score()`, 6 dataclass-grouped dimensions), plus an
  explicit map of **three separate, non-equivalent feature-computation code
  paths** in this repo: `daemon/detector/features.py` (dead code, zero
  live call sites, matches the dissertation's 8-feature description),
  `fingerprint.py`/`scorer.py` (the actually-live pipeline, 14 signals),
  and `daemon/fingerprint/packager.py` (a third, registry-only 8-element
  vector).
- **The conflict, resolved** (§4.5 of the inventory): the dissertation's
  `thread_density` name does not exist in the live scorer at all — thread
  saturation is scored directly from `thread_count` vs `cpu_count`. A
  *similarly-named but numerically different* field, `thread_cpu_ratio`
  (un-normalised `[0,2]`, only used by the fingerprint-registry gate, not
  the scorer), exists in `fingerprint.py`. `packager.py` compounds this by
  submitting `thread_cpu_ratio`'s raw value to the registry under the
  string key `"thread_density"` — a real mislabelling worth fixing before
  any cross-node registry comparison is trusted, flagged but not silently
  patched (Task 2's brief was inventory + resolution, not a code fix).

## Task 3 — figures

Three PNGs in `evaluation/figures/`, 200dpi, real values traced to existing
CSVs (score trajectory) or the feature-contribution CSV, using the
dataviz-skill categorical palette:

- `fig_score_trajectory.png` — composite score vs. elapsed time for 4 tracks
  (XMRig ground truth, UPX-packed, benign OpenSSL, benign gcc), with LOW
  /MEDIUM/HIGH/CRITICAL reference lines. Multi-PID tracks aggregated by
  worst-case score per tick (documented in-script).
- `fig_feature_contribution.png` — weighted per-feature contribution at each
  track's peak tick, XMRig vs. benign OpenSSL side by side. Required fixing
  a real bug during construction: naively keying by `(timestamp, feature_name)`
  silently let one parallel worker PID's all-zero row overwrite another's
  real contribution at a shared capture tick; fixed by keying on
  `(timestamp, pid)` together. The corrected chart shows both tracks hitting
  identical `thread_count` saturation, with XMRig additionally carrying
  RandomX-specific scratchpad/huge-page/sustained-detection weight that
  OpenSSL never accrues — a clean illustration of *why* the two are
  distinguished, not just *that* they are.
- `fig_latency_distribution.png` — histogram of the 13 scan-cycle gaps
  already published in `REPORT.md` §4, with n stated on the figure itself
  (no larger raw dataset exists to draw from this round).

## Task 4 — screenshots of the running system

Required starting the daemon live (`sudo python3 daemon/main.py`, done
twice this round with the user's help) and running a real XMRig `--bench`
process against it. Along the way, `/usr/bin/xmrig` turned out to have the
same immutable-flag/execute-bit-stripped state documented earlier in this
project for malware-corpus samples — now also affecting the apt-installed
system binary, cleared with the user's help (`chattr -i` + `chmod +x`)
before it could run.

Three PNGs in `evaluation/figures/`, rendered from real captured CLI stdout
(no GUI screenshot tool — scrot/import/gnome-screenshot — was installed in
this environment, so terminal output was re-typeset faithfully into an
image rather than screen-captured; every character shown is copied from
real output, documented in `evaluation/render_terminal_screenshots.py`):

- `screenshot_eddmc_status.png` — `eddmc status`, captured while pid 15944
  (xmrig) was actively under MEDIUM/THROTTLE (cross-referenced by timestamp
  with the other two captures).
- `screenshot_scored_process_list.png` — live `eddmc watch` table, real
  XMRig at 45.0/MEDIUM/THROTTLE alongside ~30 other real tracked processes
  on the test host, all correctly at NONE.
- `screenshot_medium_alert_breakdown.png` — `eddmc alerts` output showing
  the actual MEDIUM-tier detection with its full reason breakdown
  (thread saturation, RandomX scratchpad/huge-page signature, MAP_HUGETLB
  count).

**Not captured**: the Electron client-app GUI. No GUI screenshot tool is
installed, and the app was not launched this round — reported honestly
rather than skipped silently.

## Task 5 — false-positive case detail

`evaluation/results/false_positive_cases.md`. Of the five real
legitimate processes that were previously throttled (`fwupd`, Claude Code
CLI, VS Code, this project's own Electron client-app, `gjs`), only `fwupd`
has any exact score on record anywhere in this repo, and even that is a
**post-fix synthetic re-score** (29/LOW), not a live re-run — stated
explicitly rather than implied otherwise. As a byproduct of Task 4's live
daemon session, Claude Code CLI and VS Code were re-checked **live** this
round: both now score 0–12/NONE (well below LOW), a genuine if informal
re-confirmation that the huge-page joint-condition fix holds. The Electron
client-app and `gjs` were not re-verified (no running instance to check).

## Task 6 — confusion matrix v2 (four readings)

`evaluation/results/confusion_matrix_v2.md`, same underlying per-observation
CSVs as `EVALUATION_ROUND2.md` P1-1, decomposed to separate latency, track
scope, and threshold choice as three different factors instead of folding
them into one recall number:

| Reading | Scope | Threshold | Recall |
|---|---|---|---|
| 1 — as currently computed | all 7 positive tracks | MEDIUM+ | 0.626 |
| 2 — mining tracks only | excl. stratum-port + WASM tracks | MEDIUM+ | 0.725 |
| 3 — steady state | excl. each track's own pre-detection window | MEDIUM+ | **0.891** |
| 4 — any alert tier | all 7 positive tracks | LOW+ | 0.703 |

Precision/specificity/FPR are 1.0/1.0/0.0 in all four readings (no false
positives were introduced or removed by any of these reslicings). Reading
1→3 is the single most important number to carry into Chapter 6: roughly
two-thirds of the apparent recall gap in the headline figure is detection
**latency** (ticks before the scorer could plausibly have fired at all, by
its own temporal-gating design), not a real miss — once given its own first
alert onward, the detector achieves 89.1% recall.

## Task 7 — mitigation effect (attempted; partially inconclusive)

Required exposing the scorer's already-computed `cpu_percent` internally
(small, read-only-with-respect-to-detection-logic change: `daemon/detector/engine.py`
now persists `fp.parallelism.cpu_percent` into the process store each tick;
`evaluation/results_capture.py` now records it) and re-running one real
XMRig track. This took three attempts:

1. First attempt was killed by the host's own memory limit (this test VM
   has ~3.3GB RAM, already under real pressure from IDE/daemon/etc.) — and
   left an **orphaned xmrig process running unsupervised for ~35 minutes**
   because a `$!`-based PID capture inside a backgrounded multi-line script
   did not reliably resolve to the actual xmrig PID in this harness. Found
   and killed manually.
2. Second attempt (lighter config: `--randomx-mode=light`, 2 threads)
   completed, but its data was **contaminated by PID reuse**: the killed
   orphan's stale detection state (23 accumulated "suspicious ticks",
   already MEDIUM/THROTTLE) was still keyed under the same PID number, and
   the kernel handed that exact PID to the new process, making it look
   falsely like instant detection at t=0.
3. Third attempt, after a full daemon restart (clears all in-memory
   process-store state) and switching to `--comm`-based process matching
   instead of PID matching: clean data, real NONE→LOW→MEDIUM/THROTTLE
   progression over 90s.

**Result**: `evaluation/results/mitigation_effect.md`. The clean run
surfaced a genuine data-quality finding rather than a clean before/after
number: `cpu_percent` is empty for every pre-detection tick in the capture
and only starts being populated at the process's first LOW-tier detection
— consistent with, but not fully explained by, psutil's documented
`Process.cpu_percent(interval=None)` first-call-returns-0.0 convention.
Root cause not fully chased down this round (a resource-prioritisation
short-circuit for low-scoring PIDs upstream of `_cpu_percent()` is one
candidate, unconfirmed). Only a post-THROTTLE reading is usable (92.6%
mean CPU on 1 thread, n=23 ticks, remarkably steady — min=max=92.6) with
no trustworthy unthrottled baseline to compare it against. Reported as
attempted-but-inconclusive rather than forcing a before/after number that
the data doesn't actually support.

## Cross-cutting notes for whoever writes this into Chapter 6

- The single strongest new number from this round is **Reading 3's 89.1%
  steady-state recall** (Task 6) — it directly answers the "is the low
  headline recall a real miss or a latency artefact" question the prior
  round's P1-5 raised but didn't fully close.
- Task 1's ablation gives a defensible answer to "which feature actually
  matters": the RandomX scratchpad/huge-page joint signature, not the
  other 8 weighted signals, which are largely redundant with it once it
  fires.
- Task 2's `thread_density`/`thread_cpu_ratio`/packager mislabelling is a
  real, fixable bug worth a sentence in Chapter 6's limitations section —
  it was flagged, not patched, per this round's read-only scope.
- Task 7's inconclusive result is itself worth a sentence: it demonstrates
  the project's instrumentation gap (no clean CPU-before-enforcement
  baseline currently exists anywhere in the capture pipeline) rather than
  measuring the mitigation's real effect — a legitimate "future work" item.
