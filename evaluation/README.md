# EDDMC Evaluation Harness

Reproducible test tracks for validating EDDMC against the datasets/tools
cited across the cryptojacking-detection literature, so the results can go
straight into your thesis results section. All tracks share one instrument
(`results_capture.py`) and write to a common CSV schema under `results/`.

**Start the daemon first**, every track assumes it: `sudo python3 daemon/main.py --log-level INFO`

## Literature source → track mapping

| Cited source | Applicable to EDDMC? | Track | Why |
|---|---|---|---|
| XMRig / RandomX-style miners | Yes — direct | [`xmrig_ground_truth/`](xmrig_ground_truth/) | Real XMRig binary, `--bench` mode (offline, no pool needed) — exercises real RandomX CPU/futex/thread/scratchpad behaviour, the strongest possible ground-truth positive |
| CoinBlockerLists | Yes — via the mechanism it represents | [`network_pool_blocklist/`](network_pool_blocklist/) | EDDMC detects by destination **port**, not domain (`daemon/ebpf/net_monitor.c`); this drives that exact signal locally and safely instead of resolving live blocklisted domains |
| wasmbench, NoCoin list, MadeWithWasm | Yes — host-level, not in-browser | [`browser_wasm/`](browser_wasm/) | EDDMC monitors OS processes, not browser internals — a real WASM module run inside Chromium still produces a CPU-bound, thread-saturated *process* that the host-level features see |
| SoK: Cryptojacking Malware (hash + domain lists) | Yes — metadata source | [`malware_corpus/`](malware_corpus/) | Public hash/domain list repo, safe to clone; turning hashes into runnable binaries needs step 2 below |
| MalwareBazaar / VirusTotal / VirusShare / Hybrid Analysis / ANY.RUN | Yes — real malware, isolated only | [`malware_corpus/`](malware_corpus/) | Live samples; run only inside an isolated VM with a snapshot/revert workflow — see that track's README for the full safety protocol |
| Fileless PowerShell set (Purple Fox, Lemon Duck, Tor2Mine) | **No** — out of scope | — | Windows-only attack vector; EDDMC has no Windows agent. Report as a scope boundary, not a gap |
| Self-throttling/rate-limited miners (evasion technique reported across the literature) | Yes — direct | [`evasion_throttled_miner/`](evasion_throttled_miner/) | Real XMRig with reduced thread count; tests whether non-CPU%-based signals (scratchpad+huge-page, futex ratio) still catch a miner deliberately staying under naive CPU thresholds |
| Detector overhead (reported in MineSweeper, Outguard, CMTracker) | Yes — direct | [`detector_overhead/`](detector_overhead/) | Measures the EDDMC daemon process's own CPU%/RSS, idle vs. under active detection load |
| Packed/obfuscated binaries (signature-evasion technique) | Yes — direct | [`packed_binary/`](packed_binary/) | Runs a UPX-packed XMRig copy; EDDMC's signals are purely runtime/behavioural (post-unpack), so packing should not affect detection |
| Hardware performance counters (MineSweeper-style cache-miss/branch-predictor signals) | Not implemented | — | Would require a new perf_event_open-based collector — a new detection capability, not an eval script. Cite as related work/future work rather than reproduce |
| Falco / other eBPF-based competitive baselines | Not attempted | — | Needs a new APT repo + separate eBPF driver with uncertain compatibility on this kernel; out of scope for this harness |

## Running the safe tracks

```bash
# 1. Real XMRig, offline benchmark mode — strongest ground-truth positive
bash evaluation/xmrig_ground_truth/run_xmrig_test.sh 10M

# 2. Stratum-port detection (CoinBlockerLists mechanism), fully local
bash evaluation/network_pool_blocklist/run_pool_hits_test.sh

# 3. In-browser WASM miner-shaped load (wasmbench/NoCoin analogue)
cd evaluation/browser_wasm && npm install && node build_wasm.js && cd -
bash evaluation/browser_wasm/run_browser_test.sh 60

# 4. Self-throttled miner (evasion attempt: 1 thread instead of one-per-core)
bash evaluation/evasion_throttled_miner/run_throttled_miner_test.sh 1 3M

# 5. Detector overhead -- run baseline first, then loaded, then compare
bash evaluation/detector_overhead/run_overhead_baseline.sh 60
bash evaluation/detector_overhead/run_overhead_loaded.sh 60 3M

# 6. UPX-packed binary (requires: sudo apt install upx-ucl)
bash evaluation/packed_binary/run_packed_test.sh 3M
```

## Running the malware-corpus track

Read [`malware_corpus/README.md`](malware_corpus/README.md) in full before
running anything in that directory — it involves real, live cryptojacking
malware and a stricter safety protocol (VM snapshots, network-namespace
isolation, mandatory `--i-understand-the-risk` flag).

## Output

Every track writes `results/<label>.csv` with the same columns: score,
confidence tier, mitigation tier, per-feature raw counters (futex, mmap,
thread_count, mining_pool_hits, scratchpad_allocs, ...), and the reasons
string the scorer attached. `results_capture.py` also prints a one-line
summary per run (peak score/tier, time-to-first-alert) you can drop straight
into a results table:

| Test | Peak score | Tier reached | Time to first alert | Pool hit fired |
|---|---|---|---|---|
| XMRig ground truth | | | | |
| Network pool-hits | | | | |
| Browser WASM miner | | | | |
| Malware sample N | | | | |
