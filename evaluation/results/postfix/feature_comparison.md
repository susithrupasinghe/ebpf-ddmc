# Postfix per-feature contribution comparison

Pre-fix peak: `xmrig_ground_truth_1M.csv` t=104.0s, score=45/MEDIUM

Post-fix peak: `xmrig_postfix.csv` t=126.6s, score=52.0/MEDIUM

| Feature (weighted group) | Pre-fix contribution | Post-fix contribution | Newly nonzero? |
|---|---|---|---|
| futex (syscall barrier signal) | 0.0 | 0.0 | no |
| compute-pure (low I/O + high CPU) | 0.0 | 0.0 | no |
| thread saturation | 0.0 | 7.0 | **YES** |
| sustained high CPU% | 0.0 | 0.0 | no |
| RandomX scratchpad (weighted term) | 0.0 | 7.0 | **YES** |
| huge pages requested | 0.0 | 5.0 | **YES** |
| scheduler CPU-boundedness | 0.0 | 6.0 | **YES** |
| temporal sustained-detection | 0.0 | 7.0 | **YES** |
| pool connection (weighted term) | 0.0 | 0.0 | no |

cpu_percent used in replay: pre-fix 258.0 (recovered exactly: True), post-fix 2.0 (recovered exactly: False) — unrelated to this fix, still subject to the separate scan-cadence limitation documented in Task 7.

## Full reason text

**Pre-fix**: thread saturation: 4 threads = 4 logical CPUs; sustained CPU 258%; RandomX signature: 11 × 2MB scratchpad allocation(s) backed by huge pages (40 MB total) — strong evidence; MAP_HUGETLB requested (11 times)

**Post-fix**: thread saturation: 6 threads = 4 logical CPUs; RandomX signature: 10 × 2MB scratchpad allocation(s) backed by huge pages (38 MB total) — strong evidence; MAP_HUGETLB requested (10 times); mostly CPU-bound: 83% involuntary preemptions; sustained detection: 7 consecutive scan windows (~35s) — rules out bursty legitimate workloads

