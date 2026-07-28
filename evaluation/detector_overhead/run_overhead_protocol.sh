#!/usr/bin/env bash
# EDDMC Evaluation — P0-2 full overhead re-measurement protocol.
#
# Runs 5 trials x 300s(+) for whichever condition is requested. This script
# does NOT manage daemon start/stop itself (that needs sudo, done by the
# human operator) -- it assumes the correct daemon state (stopped for
# baseline, running fresh for the other three) is already in place when
# invoked, and fails fast with a clear message if not.
#
# Usage: bash run_overhead_protocol.sh <condition> [duration_seconds]
#   condition: baseline | idle | benign | synthetic_miner
#   duration:  seconds per trial, default 300 (work order minimum)
#
# Always runs exactly 5 trials of the given condition, labelled _t1.._t5.

set -uo pipefail

CONDITION="${1:?condition required: baseline|idle|benign|synthetic_miner}"
DURATION="${2:-300}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="${SCRIPT_DIR}/../results/overhead_protocol_${CONDITION}.log"
: > "$LOG"

log() { echo "$*" | tee -a "$LOG"; }

case "$CONDITION" in
  baseline)
    if [[ -S /tmp/eddmc.sock ]]; then
      echo "Daemon is still running -- condition 'baseline' needs it STOPPED. Stop it first (sudo systemctl stop eddmc)." >&2
      exit 1
    fi
    SCRIPT="measure_system_baseline.py"
    ;;
  idle)
    if [[ ! -S /tmp/eddmc.sock ]]; then
      echo "Daemon is not running -- condition 'idle' needs it running fresh." >&2
      exit 1
    fi
    ;;
  benign)
    if [[ ! -S /tmp/eddmc.sock ]]; then
      echo "Daemon is not running -- condition 'benign' needs it running." >&2
      exit 1
    fi
    ;;
  synthetic_miner)
    if [[ ! -S /tmp/eddmc.sock ]]; then
      echo "Daemon is not running -- condition 'synthetic_miner' needs it running." >&2
      exit 1
    fi
    ;;
  *)
    echo "Unknown condition: $CONDITION (expected baseline|idle|benign|synthetic_miner)" >&2
    exit 1
    ;;
esac

log "════════════════════════════════════════════════════════════"
log "P0-2 overhead protocol: condition=${CONDITION} duration=${DURATION}s x5 trials"
log "════════════════════════════════════════════════════════════"

RESULTS_DIR="${SCRIPT_DIR}/../results"

for i in 1 2 3 4 5; do
  log ""
  log "--- trial ${i}/5 ---"
  # measure_system_baseline.py / measure_daemon_overhead.py APPEND and resume
  # from an existing file with the same --label (built for chunking around
  # an earlier environment issue). A stale file left over from ANY earlier
  # run (this protocol or ad-hoc debugging) would otherwise be silently
  # "resumed" from its old, unrelated start time, corrupting elapsed_s with
  # a bogus multi-hour offset -- confirmed happening once already. Always
  # remove the target file first so every trial genuinely starts fresh.
  case "$CONDITION" in
    baseline)          rm -f "${RESULTS_DIR}/overhead_baseline_t${i}.csv" ;;
    idle)              rm -f "${RESULTS_DIR}/overhead_idle_baseline_t${i}.csv" ;;
    benign)            rm -f "${RESULTS_DIR}/overhead_benign_workload_active_t${i}.csv" ;;
    synthetic_miner)   rm -f "${RESULTS_DIR}/overhead_synthetic_miner_active_t${i}.csv" ;;
  esac
  case "$CONDITION" in
    baseline)
      python3 "${SCRIPT_DIR}/measure_system_baseline.py" --label "baseline_t${i}" --duration "$DURATION" 2>&1 | tee -a "$LOG"
      ;;
    idle)
      bash "${SCRIPT_DIR}/run_overhead_baseline.sh" "$DURATION" "t${i}" 2>&1 | tee -a "$LOG"
      ;;
    benign)
      bash "${SCRIPT_DIR}/run_overhead_benign.sh" "$DURATION" "t${i}" 2>&1 | tee -a "$LOG"
      ;;
    synthetic_miner)
      bash "${SCRIPT_DIR}/run_overhead_synthetic_miner.sh" "$DURATION" "t${i}" 2>&1 | tee -a "$LOG"
      ;;
  esac
done

log ""
log "Condition ${CONDITION} complete: 5 trials written to evaluation/results/overhead_*_t{1..5}.csv"
