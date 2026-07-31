# Confusion matrix v2 — four readings (Chapter 6 data extraction, Task 6)

Same underlying per-observation CSVs as `reports/EVALUATION_ROUND2.md` P1-1 (one process x one scan-tick = one observation), decomposed four ways so detection latency and track scope are visible as separate factors rather than folded into a single recall figure.

## Reading 1 — as currently computed (all tracks, MEDIUM+)

Every positive-labelled track from t=0, confidence >= MEDIUM. This is exactly `reports/EVALUATION_ROUND2.md` P1-1's reading, reproduced here for comparison.

| Source | Label | n | positive (this reading's threshold) | excluded (pre-detection) |
|---|---|---|---|---|
| `xmrig_ground_truth_1M.csv` | positive | 287 | 194 | 0 |
| `evasion_throttled_1thread_3M.csv` | positive | 293 | 185 | 0 |
| `packed_xmrig_3M.csv` | positive | 285 | 248 | 0 |
| `network_pool_blocklist_t1.csv` | positive | 25 | 0 | 0 |
| `network_pool_blocklist_t2.csv` | positive | 25 | 0 | 0 |
| `network_pool_blocklist_t3.csv` | positive | 25 | 0 | 0 |
| `browser_wasm_miner.csv` | positive | 61 | 0 | 0 |
| `benign_openssl_t1.csv` | negative | 152 | 0 | 0 |
| `benign_openssl_t2.csv` | negative | 4 | 0 | 0 |
| `benign_openssl_t3.csv` | negative | 35 | 0 | 0 |
| `benign_gcc_compile_t1.csv` | negative | 1497 | 0 | 0 |
| `benign_gcc_compile_t2.csv` | negative | 1738 | 0 | 0 |
| `benign_gcc_compile_t3.csv` | negative | 1671 | 0 | 0 |

**n = 6098. TP=627 FN=374 TN=5097 FP=0**

- Precision: 1.0000
- Recall: 0.6264
- F1: 0.7703
- Specificity: 1.0000
- False-positive rate: 0.0000

## Reading 2 — mining tracks only, MEDIUM+ (excludes stratum-port and browser-WASM tracks)

Removes network_pool_blocklist (0% recall root-caused as a scan-cycle-latency artefact, not a scoring miss — REPORT.md §4) and browser_wasm_miner (peaked at LOW/39, one point under this reading's own MEDIUM cutoff) from the positive set, isolating the three tracks where the scorer's core RandomX/CPU/thread signals are what's actually being measured.

| Source | Label | n | positive (this reading's threshold) | excluded (pre-detection) |
|---|---|---|---|---|
| `xmrig_ground_truth_1M.csv` | positive | 287 | 194 | 0 |
| `evasion_throttled_1thread_3M.csv` | positive | 293 | 185 | 0 |
| `packed_xmrig_3M.csv` | positive | 285 | 248 | 0 |
| `benign_openssl_t1.csv` | negative | 152 | 0 | 0 |
| `benign_openssl_t2.csv` | negative | 4 | 0 | 0 |
| `benign_openssl_t3.csv` | negative | 35 | 0 | 0 |
| `benign_gcc_compile_t1.csv` | negative | 1497 | 0 | 0 |
| `benign_gcc_compile_t2.csv` | negative | 1738 | 0 | 0 |
| `benign_gcc_compile_t3.csv` | negative | 1671 | 0 | 0 |

**n = 5962. TP=627 FN=238 TN=5097 FP=0**

- Precision: 1.0000
- Recall: 0.7249
- F1: 0.8405
- Specificity: 1.0000
- False-positive rate: 0.0000

## Reading 3 — steady state (excludes each track's own pre-detection window), MEDIUM+

Exclusion rule (stated once, applied uniformly): drop every tick before a track's own first LOW+ (alert-tier) detection; a track that never alerts at all contributes no steady-state window and is reported as n=0 for that file, not silently dropped. This isolates classification accuracy from detection latency, which is already reported on its own terms elsewhere (P1-5).

| Source | Label | n | positive (this reading's threshold) | excluded (pre-detection) |
|---|---|---|---|---|
| `xmrig_ground_truth_1M.csv` | positive | 219 | 194 | 68 |
| `evasion_throttled_1thread_3M.csv` | positive | 218 | 185 | 75 |
| `packed_xmrig_3M.csv` | positive | 261 | 248 | 24 |
| `network_pool_blocklist_t1.csv` | positive | 0 | 0 | 25 |
| `network_pool_blocklist_t2.csv` | positive | 0 | 0 | 25 |
| `network_pool_blocklist_t3.csv` | positive | 0 | 0 | 25 |
| `browser_wasm_miner.csv` | positive | 6 | 0 | 55 |
| `benign_openssl_t1.csv` | negative | 152 | 0 | 0 |
| `benign_openssl_t2.csv` | negative | 4 | 0 | 0 |
| `benign_openssl_t3.csv` | negative | 35 | 0 | 0 |
| `benign_gcc_compile_t1.csv` | negative | 1497 | 0 | 0 |
| `benign_gcc_compile_t2.csv` | negative | 1738 | 0 | 0 |
| `benign_gcc_compile_t3.csv` | negative | 1671 | 0 | 0 |

**n = 5801. TP=627 FN=77 TN=5097 FP=0**

- Precision: 1.0000
- Recall: 0.8906
- F1: 0.9421
- Specificity: 1.0000
- False-positive rate: 0.0000

## Reading 4 — any alert tier (all tracks, LOW+ rather than MEDIUM+)

Same track scope as Reading 1, but the positive threshold is lowered to LOW+ (any logged alert, not just mitigation-active MEDIUM+). This is where browser_wasm_miner (peak 39/LOW) converts from a miss to a hit.

| Source | Label | n | positive (this reading's threshold) | excluded (pre-detection) |
|---|---|---|---|---|
| `xmrig_ground_truth_1M.csv` | positive | 287 | 219 | 0 |
| `evasion_throttled_1thread_3M.csv` | positive | 293 | 218 | 0 |
| `packed_xmrig_3M.csv` | positive | 285 | 261 | 0 |
| `network_pool_blocklist_t1.csv` | positive | 25 | 0 | 0 |
| `network_pool_blocklist_t2.csv` | positive | 25 | 0 | 0 |
| `network_pool_blocklist_t3.csv` | positive | 25 | 0 | 0 |
| `browser_wasm_miner.csv` | positive | 61 | 6 | 0 |
| `benign_openssl_t1.csv` | negative | 152 | 0 | 0 |
| `benign_openssl_t2.csv` | negative | 4 | 0 | 0 |
| `benign_openssl_t3.csv` | negative | 35 | 0 | 0 |
| `benign_gcc_compile_t1.csv` | negative | 1497 | 0 | 0 |
| `benign_gcc_compile_t2.csv` | negative | 1738 | 0 | 0 |
| `benign_gcc_compile_t3.csv` | negative | 1671 | 0 | 0 |

**n = 6098. TP=704 FN=297 TN=5097 FP=0**

- Precision: 1.0000
- Recall: 0.7033
- F1: 0.8258
- Specificity: 1.0000
- False-positive rate: 0.0000

## Reading-to-reading takeaways

- Reading 1 -> Reading 2: removing the two latency/threshold-boundary-affected tracks shows how much of Reading 1's recall gap is those two tracks specifically, versus the three core mining tracks.
- Reading 1 -> Reading 3: shows how much of the recall gap is detection latency (pre-detection-window ticks that were never going to be positive by design) versus tracks that still don't recover even once given their own alert onward.
- Reading 1 -> Reading 4: shows how much of the recall gap is specifically the MEDIUM-vs-LOW threshold choice (mitigation-active vs merely-logged), isolating browser_wasm_miner's boundary case from network_pool_blocklist's latency case.

