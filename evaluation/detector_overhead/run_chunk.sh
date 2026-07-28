#!/usr/bin/env bash
# EDDMC Evaluation — run exactly ONE chunk of a P0-2 overhead trial.
#
# Why chunks: this evaluation session's execution environment was found to
# terminate any process (backgrounded, foregrounded, or nohup+disown
# detached) after roughly 20-30 seconds -- a change from earlier in the same
# session when 300+ second measurements ran fine. A trial is therefore built
# by calling this script repeatedly (once per tool invocation) with the same
# label; measure_system_baseline.py / measure_daemon_overhead.py append to
# the existing CSV and reconstruct the true trial start time, so the result
# reads as one continuous trial regardless of how many chunks built it.
#
# For 'benign'/'synthetic_miner', the workload process is relaunched fresh
# each chunk (it would also be killed by the same ceiling) -- there is a
# small (sub-second) gap at each chunk boundary while it restarts. This is
# an explicit, documented compromise forced by the environment constraint,
# not a silent gap.
#
# Usage: bash run_chunk.sh <condition> <label_suffix> <chunk_duration_s>
#   condition: baseline | idle | benign | synthetic_miner

set -uo pipefail
CONDITION="${1:?condition required}"
TRIAL="${2:?label suffix required}"
CHUNK="${3:-15}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(dirname "$SCRIPT_DIR")"

case "$CONDITION" in
  baseline)
    python3 "${SCRIPT_DIR}/measure_system_baseline.py" --label "baseline_${TRIAL}" --duration "$CHUNK"
    ;;
  idle)
    python3 "${SCRIPT_DIR}/measure_daemon_overhead.py" --label "idle_baseline_${TRIAL}" --duration "$CHUNK"
    ;;
  benign)
    NPROC="$(nproc)"
    timeout "$((CHUNK + 5))" openssl speed -multi "$NPROC" -seconds "$CHUNK" sha256 aes-256-cbc \
      >>"${EVAL_DIR}/results/benign_workload_active_${TRIAL}.stdout.log" 2>&1 &
    WORKLOAD_PID=$!
    python3 "${SCRIPT_DIR}/measure_daemon_overhead.py" --label "benign_workload_active_${TRIAL}" --duration "$CHUNK"
    kill "$WORKLOAD_PID" 2>/dev/null || true
    ;;
  synthetic_miner)
    python3 - "$CHUNK" <<'PY' &
import threading, time, hashlib, os, sys
duration = float(sys.argv[1])
def worker():
    data = os.urandom(64)
    end = time.time() + duration
    while time.time() < end:
        for _ in range(10000):
            hashlib.sha256(data).digest()
threads = [threading.Thread(target=worker, daemon=True) for _ in range(os.cpu_count() or 4)]
for t in threads: t.start()
for t in threads: t.join()
PY
    WORKLOAD_PID=$!
    python3 "${SCRIPT_DIR}/measure_daemon_overhead.py" --label "synthetic_miner_active_${TRIAL}" --duration "$CHUNK"
    kill "$WORKLOAD_PID" 2>/dev/null || true
    ;;
  *)
    echo "Unknown condition: $CONDITION" >&2
    exit 1
    ;;
esac
