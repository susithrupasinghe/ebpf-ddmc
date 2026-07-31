# Task: Extract evaluation data for the EDDMC thesis Results chapter

## Context

You are working in the EDDMC repository. EDDMC is an eBPF-based Linux daemon that detects and
mitigates CPU cryptojacking using deterministic weighted scoring over kernel-derived
behavioural features, with a five-tier mitigation cascade and a distributed fingerprint
registry. It is an MSc dissertation artefact.

Two evaluation rounds have already been completed. Their outputs are
`FINAL_EVALUATION_SUMMARY.md` and `reports/EVALUATION_ROUND2.md`, and capture CSVs are in
`evaluation/results/`. Between the rounds, three defects were fixed: a silent detection-thread
termination, a scratchpad heuristic that false-positived on five legitimate processes, and a
scan-latency problem that was quantified but not corrected.

The dissertation's Results chapter must now be rewritten to a required academic structure that
includes a qualitative analysis section, an ablation and sensitivity study, and a set of
figures. The existing evaluation reports cover the quantitative material adequately. They do
not contain the data needed for those three sections. Your job is to produce that data.

## Scoping: this is mostly extraction, not experimentation

With one exception (screenshots, task 4), nothing here should require running a new
experiment. It is offline recomputation and plotting from data that already exists. Do not run
new benchmark rounds to manufacture a number. If something cannot be produced from existing
data, say so and stop; a documented gap is fine and a fabricated figure is not.

## Ground rules

- Never invent a value. Every number must trace to a CSV, a log line, or code you can point at.
- Do not silently drop failing or empty results. If a track has no usable data, report that.
- Record the git SHA. Commit before any run that produces data.
- Emit machine-readable output (CSV or JSON) alongside any human-readable summary.
- Do not tune thresholds or change scoring behaviour. This task is read-only with respect to
  detection logic.

---

## Task 0 — Start here, this determines everything else

Inspect the capture CSVs in `evaluation/results/` and report their exact schema.

**The critical question: do the CSVs retain raw per-feature values per tick, or only the
composite score and tier?**

Report the answer explicitly before doing anything else, because Task 1 depends entirely on
it. Also list which tracks are present, their row counts, and their capture interval.

---

## Task 1 — Feature contribution and ablation (highest priority)

A per-feature contribution trace was instrumented in the previous round but never persisted.
An entire required chapter section depends on this data.

**If Task 0 shows raw feature values are present**, recompute contributions offline. No re-run
needed. For one representative XMRig track and one benign track, write one row per feature per
tick to `evaluation/results/feature_contributions.csv`:

```
timestamp, pid, feature_name, raw_value, normalised_value, weight, contribution,
floor_engaged, running_score, tier
```

**Then produce the leave-one-out ablation.** At the peak-score tick of each mining track,
recompute the composite score with each feature zeroed in turn. Write
`evaluation/results/ablation_leave_one_out.md` containing:

| Feature removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |

This table answers which features actually carry detection and which are redundant. It is the
core evidence for the ablation section.

**If Task 0 shows raw values are absent**, say so plainly, then persist the instrumentation and
capture one 300-second XMRig run and one benign run with it enabled. This is the only case in
which a re-run is justified in this task list.

---

## Task 2 — Artefact inventory

An inventory was reported complete in the previous round but is not in the repository, or has
not been shared. Produce or locate `docs/ARTEFACT_INVENTORY.md` stating:

- Every feature the scorer consumes: exact name as used in code, source collector, weight,
  normalisation method, and whether it is eligible for a hard-evidence floor.
- Every hard-evidence floor: its trigger condition and floor value.
- The tier boundaries as implemented, and the mitigation action bound to each tier.
- Every eBPF program: filename, attach point (tracepoint or kprobe), and what it populates.

**One specific conflict to resolve.** The dissertation documents a feature called
`thread_density`; the evaluation output refers to `thread_cpu_ratio`. Report which name the
code actually uses. Add a short "divergences from the dissertation" section listing anything
else where the implementation has moved ahead of what is documented.

---

## Task 3 — Figures

Save PNGs at 150 dpi or higher into `evaluation/figures/`. Include axis labels and legends.
Omit chart titles; captions are added in the dissertation.

- **`fig_score_trajectory.png`** — Composite score against elapsed seconds, one line per track:
  XMRig ground truth, XMRig UPX packed, OpenSSL benign, GCC benign. Draw horizontal reference
  lines at the LOW, MEDIUM, HIGH and CRITICAL tier boundaries. This is the single most valuable
  figure; it shows workload separation, detection latency and the score ceiling at once.
- **`fig_feature_contribution.png`** — Bar chart of each feature's contribution at peak score,
  XMRig beside a benign workload. Depends on Task 1.
- **`fig_latency_distribution.png`** — Histogram or box plot of observed scan cycle gaps, with
  the configured 5-second interval marked.

---

## Task 4 — Screenshots (the only task requiring the running system)

Terminal captures at readable resolution into `evaluation/figures/`:

- `eddmc status` with the daemon running and at least one process under active mitigation.
- A scored process list with tiers visible.
- An alert emission for a MEDIUM-tier detection, showing the score breakdown if the CLI
  exposes one.
- The Electron interface, if it is in a demonstrable state. If it is not, say so.

Redact hostnames, usernames, IP addresses and any wallet strings before saving.

---

## Task 5 — False-positive case detail

Before the huge-page fix, five legitimate processes were detected and actively throttled,
including the system firmware update daemon. Only that one process currently has a score
recorded. For each of the five, write `evaluation/results/false_positive_cases.md`:

| Process | Score before fix | Tier | Mitigation applied | Score after fix | Tier after |

If the pre-fix scores were not retained in any log or capture, state that. Post-fix scores
alone remain usable.

---

## Task 6 — Confusion matrix decomposition

The existing matrix assigns ground truth per file, so every observation from process start
counts as positive, including the interval before the detector could have accumulated
evidence. This folds detection latency into recall. Recompute from the same CSVs and write
`evaluation/results/confusion_matrix_v2.md` with four readings, each stating n:

1. As currently computed: all tracks, MEDIUM tier and above.
2. Mining tracks only, excluding the stratum port and browser WASM tracks.
3. Steady state, excluding each run's pre-detection window. State and justify the exclusion
   rule in one sentence.
4. Any alert tier, LOW and above, rather than MEDIUM and above.

Report precision, recall, F1, specificity and false-positive rate for each.

---

## Task 7 — Mitigation effect (optional, only if it is a small change)

Previous attempts to measure throttling effect failed because the scheduler on-CPU counter
updates on a coarser cadence than the capture interval. If the feature extractor already
computes a process-level utilisation value internally for scoring, expose it in the capture
schema and re-run one XMRig track. This converts "the quota was applied" into "the quota
reduced utilisation by X", which is what the research question actually asks. Skip if it is
not small.

---

## Report back

Write `reports/CH6_DATA_EXTRACTION.md` stating, for each task: satisfied from existing data /
required a re-run / could not be produced, and why. Open the report with the answer to Task 0,
since that single fact determines how much of the ablation section can be written.

List every file produced with its path.
