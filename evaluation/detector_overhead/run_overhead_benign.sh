#!/usr/bin/env bash
# EDDMC Evaluation — daemon overhead while a benign high-CPU workload
# (OpenSSL speed) is active (P0-2 condition 3).
# Usage: bash run_overhead_benign.sh [duration_seconds] [trial_label_suffix]
set -euo pipefail
DURATION="${1:-300}"
TRIAL="${2:-}"
LABEL="benign_workload_active${TRIAL:+_${TRIAL}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(dirname "$SCRIPT_DIR")"
NPROC="$(nproc)"

if [[ ! -S /tmp/eddmc.sock ]]; then
  echo "eddmc daemon is not running." >&2
  exit 1
fi

echo "[overhead-benign] starting openssl speed -multi ${NPROC} for ${DURATION}s..."
openssl speed -multi "$NPROC" -seconds "$DURATION" sha256 aes-256-cbc \
  >"${EVAL_DIR}/results/${LABEL}.stdout.log" 2>&1 &
WORKLOAD_PID=$!

python3 "${SCRIPT_DIR}/measure_daemon_overhead.py" --label "${LABEL}" --duration "${DURATION}" --interval 1

kill "$WORKLOAD_PID" 2>/dev/null || true
wait "$WORKLOAD_PID" 2>/dev/null || true
echo "[overhead-benign] done."
