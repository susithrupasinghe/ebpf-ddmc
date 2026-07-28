#!/usr/bin/env bash
# EDDMC Evaluation — daemon overhead, idle baseline (no deliberate test workload).
# Usage: bash run_overhead_baseline.sh [duration_seconds] [trial_label_suffix]
set -euo pipefail
DURATION="${1:-60}"
TRIAL="${2:-}"
LABEL="idle_baseline${TRIAL:+_${TRIAL}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -S /tmp/eddmc.sock ]]; then
  echo "eddmc daemon is not running." >&2
  exit 1
fi

python3 "${SCRIPT_DIR}/measure_daemon_overhead.py" --label "${LABEL}" --duration "${DURATION}" --interval 1
