#!/usr/bin/env bash
# EDDMC Evaluation — XMRig ground-truth positive control.
#
# Runs the REAL, unmodified XMRig binary (RandomX/Monero miner — the exact
# family cited in the literature as the CPU-cryptojacking archetype) in its
# built-in self-contained benchmark mode. --bench needs no pool, no network,
# no wallet: it just hashes N RandomX rounds across all cores and exits, so
# this is 100% safe and reproducible, but it still drives the same signals
# EDDMC's scorer targets (futex-heavy thread sync, CPU-bound, thread count
# == core count, 2MB RandomX scratchpad allocations, huge pages).
#
# Usage:
#   sudo bash run_xmrig_test.sh [bench_preset] [poll_interval]
#   bench_preset: 1M..10M (hash count), default 10M (~30-90s on most CPUs)
#   poll_interval: results_capture.py poll interval in seconds, default 1
#
# Requires: eddmc daemon already running (sudo python3 daemon/main.py ...)
#           xmrig installed (apt install xmrig)

set -euo pipefail

PRESET="${1:-10M}"
INTERVAL="${2:-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(dirname "$SCRIPT_DIR")"
SOCK="/tmp/eddmc.sock"

if [[ ! -S "$SOCK" ]]; then
  echo "eddmc daemon is not running (no socket at $SOCK)." >&2
  echo "Start it first: sudo python3 daemon/main.py --log-level INFO" >&2
  exit 1
fi

if ! command -v xmrig &>/dev/null; then
  echo "xmrig not found. Install with: sudo apt install xmrig" >&2
  exit 1
fi

echo "[xmrig] Starting real XMRig benchmark (--bench=${PRESET})..."
xmrig --bench="${PRESET}" --no-color >"${EVAL_DIR}/results/xmrig_ground_truth_${PRESET}.stdout.log" 2>&1 &
XMRIG_PID=$!
echo "[xmrig] pid=${XMRIG_PID}"

python3 "${EVAL_DIR}/results_capture.py" \
  --label "xmrig_ground_truth_${PRESET}" \
  --pid "${XMRIG_PID}" \
  --until-exit \
  --interval "${INTERVAL}" \
  --max-duration 300

# Once EDDMC throttles this process, it can keep running for many minutes
# past the capture window (cgroup quota slows it, doesn't stop it) -- the
# interesting data is already captured, so end it now rather than block
# indefinitely on `wait`.
kill "${XMRIG_PID}" 2>/dev/null || true
sleep 1
kill -9 "${XMRIG_PID}" 2>/dev/null || true
wait "${XMRIG_PID}" 2>/dev/null || true
echo "[xmrig] benchmark finished — stdout at ${EVAL_DIR}/results/xmrig_ground_truth_${PRESET}.stdout.log"
tail -n 5 "${EVAL_DIR}/results/xmrig_ground_truth_${PRESET}.stdout.log" || true
