#!/usr/bin/env bash
# EDDMC Evaluation — self-throttled/rate-limited miner evasion test.
#
# Real cryptojacking malware often deliberately caps its own CPU usage
# (e.g. 20-50%) specifically to stay under naive CPU-threshold detectors.
# This runs real XMRig with a reduced thread count (the same effect --
# fewer threads means lower aggregate CPU% and lower thread-saturation
# ratio) to test whether EDDMC's non-CPU-percentage signals (RandomX
# scratchpad/huge-page signature, futex ratio) still catch a miner that
# never crosses a CPU%-based threshold.
#
# Usage:
#   sudo bash run_throttled_miner_test.sh [threads] [bench_preset] [poll_interval]
#   threads: CPU threads XMRig uses (default 1 -- the most aggressive
#            evasion attempt: single-threaded instead of one-per-core)
#   bench_preset: 1M..10M, default 3M (fewer threads hash slower, so a
#                 smaller preset keeps the run to a reasonable duration)
#
# Compare this run's CSV against evaluation/results/xmrig_ground_truth_*.csv
# (full thread count) to see whether detection timeline/tier changes.
#
# Requires: eddmc daemon already running (sudo python3 daemon/main.py ...)
#           xmrig installed (apt install xmrig)

set -euo pipefail

THREADS="${1:-1}"
PRESET="${2:-3M}"
INTERVAL="${3:-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(dirname "$SCRIPT_DIR")"
SOCK="/tmp/eddmc.sock"
LABEL="evasion_throttled_${THREADS}thread_${PRESET}"

if [[ ! -S "$SOCK" ]]; then
  echo "eddmc daemon is not running (no socket at $SOCK)." >&2
  echo "Start it first: sudo python3 daemon/main.py --log-level INFO" >&2
  exit 1
fi

if ! command -v xmrig &>/dev/null; then
  echo "xmrig not found. Install with: sudo apt install xmrig" >&2
  exit 1
fi

echo "[throttled] Starting rate-limited XMRig: --threads=${THREADS} --bench=${PRESET}"
echo "[throttled] (evasion attempt: fewer threads = lower CPU%/thread-saturation signals)"
xmrig --bench="${PRESET}" --threads="${THREADS}" --no-color \
  >"${EVAL_DIR}/results/${LABEL}.stdout.log" 2>&1 &
XMRIG_PID=$!
echo "[throttled] pid=${XMRIG_PID}"

python3 "${EVAL_DIR}/results_capture.py" \
  --label "${LABEL}" \
  --pid "${XMRIG_PID}" \
  --until-exit \
  --interval "${INTERVAL}" \
  --max-duration 300

# See run_xmrig_test.sh for why this doesn't just `wait`: a throttled
# process can run for many minutes past the capture window.
kill "${XMRIG_PID}" 2>/dev/null || true
sleep 1
kill -9 "${XMRIG_PID}" 2>/dev/null || true
wait "${XMRIG_PID}" 2>/dev/null || true
echo "[throttled] benchmark finished — stdout at ${EVAL_DIR}/results/${LABEL}.stdout.log"
tail -n 5 "${EVAL_DIR}/results/${LABEL}.stdout.log" || true
