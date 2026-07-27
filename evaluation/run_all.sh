#!/usr/bin/env bash
# EDDMC Evaluation — run every test track in sequence and log everything.
#
# Order matters: benign baseline runs FIRST (clean state, nothing mitigated
# yet), then true-positive/evasion tracks, then overhead, then the browser
# track last (heaviest external dependency). A track that fails is logged
# and skipped rather than aborting the whole run -- see the summary printed
# at the end for what actually completed.
#
# Usage: bash run_all.sh
# Requires: eddmc daemon already running (sudo python3 daemon/main.py ...)
#           xmrig, upx-ucl installed; for the browser track, CHROME_PATH set
#           on arm64 hosts (see evaluation/browser_wasm/run_browser_test.sh)

set -uo pipefail

EVAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="${EVAL_DIR}/results/run_all.log"
SOCK="/tmp/eddmc.sock"
mkdir -p "${EVAL_DIR}/results"
: > "$LOG"

FAILED=()
SKIPPED=()
PASSED=()

log() { echo "$*" | tee -a "$LOG"; }

if [[ ! -S "$SOCK" ]]; then
  echo "eddmc daemon is not running (no socket at $SOCK)." >&2
  echo "Start it first: sudo python3 daemon/main.py --log-level INFO" >&2
  exit 1
fi

run_track() {
  local name="$1"; shift
  log ""
  log "════════════════════════════════════════════════════════════"
  log "▶ ${name}"
  log "════════════════════════════════════════════════════════════"
  if "$@" >>"$LOG" 2>&1; then
    log "✓ ${name} completed"
    PASSED+=("$name")
  else
    log "✗ ${name} FAILED (exit $?) -- see log above for this section"
    FAILED+=("$name")
  fi
}

START=$(date +%s 2>/dev/null || echo 0)

for trial in 1 2 3; do
  run_track "Benign baseline trial ${trial}/3 (OpenSSL + gcc)" \
    bash "${EVAL_DIR}/benign_baseline/run_benign_test.sh" 30 "t${trial}"
done

run_track "XMRig ground truth (--bench=1M)" \
  bash "${EVAL_DIR}/xmrig_ground_truth/run_xmrig_test.sh" 1M 1

run_track "Self-throttled miner evasion (1 thread, --bench=3M)" \
  bash "${EVAL_DIR}/evasion_throttled_miner/run_throttled_miner_test.sh" 1 3M 1

if command -v upx &>/dev/null; then
  run_track "UPX-packed binary (--bench=3M)" \
    bash "${EVAL_DIR}/packed_binary/run_packed_test.sh" 3M 1
else
  log "⊘ Skipping UPX-packed track -- upx not installed (sudo apt install upx-ucl)"
  SKIPPED+=("UPX-packed binary")
fi

for trial in 1 2 3; do
  run_track "Network pool-hits trial ${trial}/3 (stratum ports)" \
    bash "${EVAL_DIR}/network_pool_blocklist/run_pool_hits_test.sh" 2 "t${trial}"
done

if [[ -n "${CHROME_PATH:-}" ]] && [[ -d "${EVAL_DIR}/browser_wasm/node_modules/puppeteer" ]]; then
  run_track "Browser WASM miner (60s)" \
    env CHROME_PATH="${CHROME_PATH}" bash "${EVAL_DIR}/browser_wasm/run_browser_test.sh" 60
else
  log "⊘ Skipping browser WASM track -- CHROME_PATH not set or node_modules/puppeteer missing"
  log "  (cd evaluation/browser_wasm && npm install && node build_wasm.js, then export CHROME_PATH=...)"
  SKIPPED+=("Browser WASM miner")
fi

run_track "Detector overhead -- idle baseline (60s)" \
  bash "${EVAL_DIR}/detector_overhead/run_overhead_baseline.sh" 60

run_track "Detector overhead -- under active load (60s)" \
  bash "${EVAL_DIR}/detector_overhead/run_overhead_loaded.sh" 60 3M

END=$(date +%s 2>/dev/null || echo 0)

log ""
log "════════════════════════════════════════════════════════════"
log "RUN COMPLETE ($(( END - START ))s total)"
log "  Passed:  ${#PASSED[@]}  (${PASSED[*]:-none})"
log "  Failed:  ${#FAILED[@]}  (${FAILED[*]:-none})"
log "  Skipped: ${#SKIPPED[@]}  (${SKIPPED[*]:-none})"
log "════════════════════════════════════════════════════════════"
log ""
log "Next: python3 ${EVAL_DIR}/generate_report.py"

[[ ${#FAILED[@]} -eq 0 ]]
