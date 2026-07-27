#!/usr/bin/env bash
# EDDMC Evaluation — network / stratum-port detection test.
#
# Validates the same detection dimension the CoinBlockerLists dataset is
# cited for in the literature (known mining-pool endpoints), reproduced
# locally and safely: instead of resolving real blocklisted domains and
# reaching out to live pool infrastructure, this drives EDDMC's own
# port-based pool_hits signal (daemon/ebpf/net_monitor.c) against local
# mock listeners on every port EDDMC recognises.
#
# Usage: bash run_pool_hits_test.sh [pause_between_ports] [trial_label_suffix]
# Requires: eddmc daemon already running (sudo python3 daemon/main.py ...)

set -euo pipefail

PAUSE="${1:-2}"
TRIAL="${2:-}"
LABEL="network_pool_blocklist${TRIAL:+_${TRIAL}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(dirname "$SCRIPT_DIR")"
SOCK="/tmp/eddmc.sock"

if [[ ! -S "$SOCK" ]]; then
  echo "eddmc daemon is not running (no socket at $SOCK)." >&2
  echo "Start it first: sudo python3 daemon/main.py --log-level INFO" >&2
  exit 1
fi

echo "[pool-hits] starting mock stratum-port listeners..."
python3 "${SCRIPT_DIR}/mock_pool_listener.py" &
LISTENER_PID=$!
sleep 1

echo "[pool-hits] starting test client..."
python3 "${SCRIPT_DIR}/pool_connect_client.py" --pause "${PAUSE}" &
CLIENT_PID=$!

python3 "${EVAL_DIR}/results_capture.py" \
  --label "${LABEL}" \
  --pid "${CLIENT_PID}" \
  --until-exit \
  --interval 1 \
  --max-duration 120

wait "${CLIENT_PID}" 2>/dev/null || true
kill "${LISTENER_PID}" 2>/dev/null || true
echo "[pool-hits] test complete."
