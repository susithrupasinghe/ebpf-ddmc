#!/usr/bin/env bash
# EDDMC Evaluation — daemon overhead while actively detecting + mitigating
# a real miner (xmrig --bench running concurrently). Compare against
# results/overhead_idle_baseline.csv to see the cost of active detection.
# Usage: bash run_overhead_loaded.sh [duration_seconds] [bench_preset]
set -euo pipefail
DURATION="${1:-60}"
PRESET="${2:-3M}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(dirname "$SCRIPT_DIR")"

if [[ ! -S /tmp/eddmc.sock ]]; then
  echo "eddmc daemon is not running." >&2
  exit 1
fi
if ! command -v xmrig &>/dev/null; then
  echo "xmrig not found. Install with: sudo apt install xmrig" >&2
  exit 1
fi

echo "[overhead-loaded] starting xmrig --bench=${PRESET} in the background..."
xmrig --bench="${PRESET}" --no-color >"${EVAL_DIR}/results/overhead_loaded_xmrig.stdout.log" 2>&1 &
XMRIG_PID=$!

python3 "${SCRIPT_DIR}/measure_daemon_overhead.py" --label under_load --duration "${DURATION}" --interval 1

kill "$XMRIG_PID" 2>/dev/null || true
wait "$XMRIG_PID" 2>/dev/null || true
echo "[overhead-loaded] done."
