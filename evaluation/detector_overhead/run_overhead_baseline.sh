#!/usr/bin/env bash
# EDDMC Evaluation — daemon overhead, idle baseline (nothing else running).
# Usage: bash run_overhead_baseline.sh [duration_seconds]
set -euo pipefail
DURATION="${1:-60}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -S /tmp/eddmc.sock ]]; then
  echo "eddmc daemon is not running." >&2
  exit 1
fi

python3 "${SCRIPT_DIR}/measure_daemon_overhead.py" --label idle_baseline --duration "${DURATION}" --interval 1
