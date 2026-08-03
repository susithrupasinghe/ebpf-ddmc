# Artifact Delta — what changed since the previous evaluation

## Verdict up front

**Nothing in the detection pipeline changed.** `git log` on `daemon/detector/scorer.py` and
`daemon/detector/fingerprint.py` shows zero commits across this entire engagement (their
most recent commits — `2aa1e8c`, `43adbb4`, `11a39ca`, `041d7f4` — predate every round covered
by `reports/FINAL_EVALUATION.md`). The effective running configuration
(`daemon/config/defaults.yaml` merged with `daemon/config/local.yaml`) matches
`DEFAULT_WEIGHTS`, `DEFAULT_POOL_FLOOR`, `DEFAULT_SCRATCHPAD_FLOOR`, and
`DEFAULT_TIER_BOUNDS` in `scorer.py` exactly — no weight, floor, or tier boundary has ever
diverged from what is hard-coded there.

| Feature/weight/floor/boundary | Before | After |
|---|---|---|
| All 14 feature weights (`DEFAULT_WEIGHTS`) | unchanged | unchanged |
| `pool_floor` (hard-evidence floor) | 50 | 50 |
| `scratchpad_floor` (hard-evidence floor) | 45 | 45 |
| Tier boundaries (alert/throttle/block/terminate) | 20/40/60/80 | 20/40/60/80 |

This is a **correction of a misreading**, not a recalibration or new functionality: no design
decision was made and none is needed, because there is nothing to document changing.

## Why the two cited figures both look real, and why they don't contradict each other

The reevaluation prompt's premise was that XMRig "now" reaches CRITICAL where it previously
reached 45.0–46.0/MEDIUM for "the same workload." Checked directly against the actual data
already on disk from the prior round:

- `evaluation/results/postfix/xmrig_postfix.csv` — XMRig with **no pool connection**
  (`mining_pool_hits=0` at its peak observation) — peaks at **score=52.0, confidence=MEDIUM**.
  This is in the same tier and the same rough magnitude as the "45.0–46.0 MEDIUM" figure: both
  are explained by `DEFAULT_SCRATCHPAD_FLOOR=45` alone doing almost all of the work (RandomX
  scratchpad + huge pages, no network evidence), with a handful of additional weighted points
  (thread saturation, CPU-bound ratio) on top.
- The cascade workload (XMRig connected to the local mock stratum listener) peaks at
  **score=100.0, confidence=CRITICAL** — reproduced across 3 trials in the prior round plus
  one additional re-verification trial this round (`reports/FINAL_EVALUATION.md` §3),
  explained by `pool_connection` firing (+40 weighted, then floored to at least
  `DEFAULT_POOL_FLOOR=50`) on top of the same scratchpad/CPU/thread signals.

These are **two different, already-measured test conditions for the same binary** — with vs.
without a confirmed stratum-port connection — not a before/after of the same condition across
a code change. Both figures were already present in this project's own results before this
prompt was written.

## Consequence for Chapter 6's central analytical finding

The finding that detection is carried by a hard-evidence floor rather than by the breadth of
the weighted model **still holds, and is reconfirmed rather than undermined**: the no-pool
ground-truth capture is pinned near the scratchpad floor (45) regardless of the weighted
sum beneath it, and the pool-connected case is pinned near the pool floor (50) the same way,
with the weighted contributions from other dimensions adding the remainder on top of each
floor rather than driving the tier crossing themselves. Task 3 of this re-evaluation computes
the exact pre-floor weighted sums for both conditions on the freshly recaptured data (see
`reports/FINAL_EVALUATION_V2.md` §3) so this claim is re-verified on current evidence, not
just re-asserted from the delta above.

## What this re-evaluation still does

Given the premise did not hold under direct verification, this re-evaluation proceeds as a
**fresh, from-scratch recapture and re-analysis against the current (unchanged) artifact**,
per the user's explicit instruction to run it in full regardless. All data is written to
`evaluation/results/final_v2/`, leaving the existing `evaluation/results/final/` set and
`reports/FINAL_EVALUATION.md` untouched, so both remain independently inspectable.
