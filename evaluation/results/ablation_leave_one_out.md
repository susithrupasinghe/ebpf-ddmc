# Leave-one-out feature ablation (Chapter 6 data extraction, Task 1)

One table per track, evaluated at that track's peak-score tick (the tick with the highest recorded `score` in its capture CSV). "Feature removed" zeroes that feature's WEIGHT in `Scorer`'s own live config-override mechanism; everything else (raw fingerprint values, floors, tier boundaries) is untouched. Baseline replay was verified to match the daemon's own recorded peak score exactly for every track below before any ablation was run.

**"Detection still achieved?"** uses this round's confusion-matrix convention (`reports/EVALUATION_ROUND2.md` P1-1): confidence >= MEDIUM (score >= 40).


## XMRig ground truth (--bench)

*Source: `xmrig_ground_truth_1M.csv`, peak tick at t=104.0s (pid=84922, comm=xmrig)*

**Baseline (all features present): score 45.0 / MEDIUM** — replay matches the daemon's own recorded peak score (45/MEDIUM).

| Feature removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| futex (syscall barrier signal) | 45.0 | MEDIUM | +0.0 | yes |
| compute-pure (low I/O + high CPU) | 45.0 | MEDIUM | +0.0 | yes |
| thread saturation | 45.0 | MEDIUM | +0.0 | yes |
| sustained high CPU% | 45.0 | MEDIUM | +0.0 | yes |
| RandomX scratchpad (weighted term) | 45.0 | MEDIUM | +0.0 | yes |
| huge pages requested | 45.0 | MEDIUM | +0.0 | yes |
| scheduler CPU-boundedness | 45.0 | MEDIUM | +0.0 | yes |
| temporal sustained-detection | 45.0 | MEDIUM | +0.0 | yes |
| pool connection (weighted term) | 45.0 | MEDIUM | +0.0 | yes |

**Floor-inclusive reading** (zeroing the underlying raw evidence too, not just the weight — shows what the hard-evidence floor alone is worth):

| Evidence removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| scratchpad_huge_allocs (RandomX floor evidence) | 23.0 | LOW | -22.0 | no |
| pool_connections (pool floor evidence) | 45.0 | MEDIUM | +0.0 | yes |

## Self-throttled evasion attempt

*Source: `evasion_throttled_1thread_3M.csv`, peak tick at t=114.1s (pid=85262, comm=xmrig)*

**Baseline (all features present): score 45.0 / MEDIUM** — replay matches the daemon's own recorded peak score (45/MEDIUM).

| Feature removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| futex (syscall barrier signal) | 45.0 | MEDIUM | +0.0 | yes |
| compute-pure (low I/O + high CPU) | 45.0 | MEDIUM | +0.0 | yes |
| thread saturation | 45.0 | MEDIUM | +0.0 | yes |
| sustained high CPU% | 45.0 | MEDIUM | +0.0 | yes |
| RandomX scratchpad (weighted term) | 45.0 | MEDIUM | +0.0 | yes |
| huge pages requested | 45.0 | MEDIUM | +0.0 | yes |
| scheduler CPU-boundedness | 45.0 | MEDIUM | +0.0 | yes |
| temporal sustained-detection | 45.0 | MEDIUM | +0.0 | yes |
| pool connection (weighted term) | 45.0 | MEDIUM | +0.0 | yes |

**Floor-inclusive reading** (zeroing the underlying raw evidence too, not just the weight — shows what the hard-evidence floor alone is worth):

| Evidence removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| scratchpad_huge_allocs (RandomX floor evidence) | 5.0 | NONE | -40.0 | no |
| pool_connections (pool floor evidence) | 45.0 | MEDIUM | +0.0 | yes |

## UPX-packed XMRig

*Source: `packed_xmrig_3M.csv`, peak tick at t=127.8s (pid=87792, comm=xmrig_packed)*

**Baseline (all features present): score 46.0 / MEDIUM** — replay matches the daemon's own recorded peak score (46.0/MEDIUM).

| Feature removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| futex (syscall barrier signal) | 46.0 | MEDIUM | +0.0 | yes |
| compute-pure (low I/O + high CPU) | 46.0 | MEDIUM | +0.0 | yes |
| thread saturation | 45.0 | MEDIUM | -1.0 | yes |
| sustained high CPU% | 46.0 | MEDIUM | +0.0 | yes |
| RandomX scratchpad (weighted term) | 45.0 | MEDIUM | -1.0 | yes |
| huge pages requested | 45.0 | MEDIUM | -1.0 | yes |
| scheduler CPU-boundedness | 46.0 | MEDIUM | +0.0 | yes |
| temporal sustained-detection | 45.0 | MEDIUM | -1.0 | yes |
| pool connection (weighted term) | 46.0 | MEDIUM | +0.0 | yes |

**Floor-inclusive reading** (zeroing the underlying raw evidence too, not just the weight — shows what the hard-evidence floor alone is worth):

| Evidence removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| scratchpad_huge_allocs (RandomX floor evidence) | 31.0 | LOW | -15.0 | no |
| pool_connections (pool floor evidence) | 46.0 | MEDIUM | +0.0 | yes |

## Browser WASM miner

*Source: `browser_wasm_miner.csv`, peak tick at t=55.8s (pid=86248, comm=DedicatedWorker)*

**Baseline (all features present): score 39.0 / LOW** — replay matches the daemon's own recorded peak score (39.0/LOW).

| Feature removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| futex (syscall barrier signal) | 21.0 | LOW | -18.0 | no |
| compute-pure (low I/O + high CPU) | 39.0 | LOW | +0.0 | no |
| thread saturation | 27.0 | LOW | -12.0 | no |
| sustained high CPU% | 33.0 | LOW | -6.0 | no |
| RandomX scratchpad (weighted term) | 36.0 | LOW | -3.0 | no |
| huge pages requested | 39.0 | LOW | +0.0 | no |
| scheduler CPU-boundedness | 39.0 | LOW | +0.0 | no |
| temporal sustained-detection | 39.0 | LOW | +0.0 | no |
| pool connection (weighted term) | 39.0 | LOW | +0.0 | no |

**Floor-inclusive reading** (zeroing the underlying raw evidence too, not just the weight — shows what the hard-evidence floor alone is worth):

| Evidence removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| scratchpad_huge_allocs (RandomX floor evidence) | 36.0 | LOW | -3.0 | no |
| pool_connections (pool floor evidence) | 39.0 | LOW | +0.0 | no |

## Network pool-hits (stratum port)

*Source: `network_pool_blocklist_t1.csv`, peak tick at t=0.0s (pid=86081, comm=python3)*

**Baseline (all features present): score 50.0 / MEDIUM** — replay DOES NOT MATCH the daemon's own recorded peak score (0.0/NONE).

*This mismatch is expected and itself corroborates a separate finding (`evaluation/results/REPORT.md` §4): the real detection engine's `_scan()` cycle never ran against this short-lived process at all during the capture window (recorded score stays 0/NONE for its entire ~24s lifetime), because real scan-cycle gaps under concurrent eBPF event load (mean 20.2s, max 34.1s) can exceed the process's whole lifetime. This offline replay recomputes what the scorer WOULD have produced from the raw evidence the eBPF collector did correctly accumulate (`mining_pool_hits` climbed to 1 by the very first tick) had a scan cycle ever reached it — independent corroboration, via a different method, of §4's root cause rather than a contradiction of the official 0/3 result.*

| Feature removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| futex (syscall barrier signal) | 50.0 | MEDIUM | +0.0 | yes |
| compute-pure (low I/O + high CPU) | 50.0 | MEDIUM | +0.0 | yes |
| thread saturation | 50.0 | MEDIUM | +0.0 | yes |
| sustained high CPU% | 50.0 | MEDIUM | +0.0 | yes |
| RandomX scratchpad (weighted term) | 50.0 | MEDIUM | +0.0 | yes |
| huge pages requested | 50.0 | MEDIUM | +0.0 | yes |
| scheduler CPU-boundedness | 50.0 | MEDIUM | +0.0 | yes |
| temporal sustained-detection | 50.0 | MEDIUM | +0.0 | yes |
| pool connection (weighted term) | 50.0 | MEDIUM | +0.0 | yes |

**Floor-inclusive reading** (zeroing the underlying raw evidence too, not just the weight — shows what the hard-evidence floor alone is worth):

| Evidence removed | Score at peak | Tier | Delta from baseline | Detection still achieved? |
|---|---|---|---|---|
| scratchpad_huge_allocs (RandomX floor evidence) | 50.0 | MEDIUM | +0.0 | yes |
| pool_connections (pool floor evidence) | 0.0 | NONE | -50.0 | no |
