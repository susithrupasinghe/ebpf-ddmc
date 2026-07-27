#!/usr/bin/env bash
# EDDMC Evaluation — UPX-packed binary test.
#
# Packs a copy of the real XMRig binary with UPX, then runs it exactly like
# the ground-truth test. Static/signature-based tools (hash matching, string
# scanning of the binary) would typically be defeated by packing -- this
# tests whether EDDMC's purely runtime/behavioural signals (RandomX
# scratchpad+huge-page allocations, futex ratio, thread saturation) are
# unaffected, since they only observe the process's actual syscalls/memory/
# scheduling behaviour AFTER the UPX stub unpacks it in memory, not the
# on-disk binary layout.
#
# Usage: sudo bash run_packed_test.sh [bench_preset] [poll_interval]
# Requires: eddmc daemon running, xmrig installed, upx-ucl installed
#           (sudo apt install upx-ucl)

set -euo pipefail

PRESET="${1:-3M}"
INTERVAL="${2:-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(dirname "$SCRIPT_DIR")"
SOCK="/tmp/eddmc.sock"
LABEL="packed_xmrig_${PRESET}"
PACKED_BIN="${SCRIPT_DIR}/xmrig_packed"

if [[ ! -S "$SOCK" ]]; then
  echo "eddmc daemon is not running (no socket at $SOCK)." >&2
  echo "Start it first: sudo python3 daemon/main.py --log-level INFO" >&2
  exit 1
fi

if ! command -v xmrig &>/dev/null; then
  echo "xmrig not found. Install with: sudo apt install xmrig" >&2
  exit 1
fi

if ! command -v upx &>/dev/null; then
  echo "upx not found. Install with: sudo apt install upx-ucl" >&2
  exit 1
fi

XMRIG_SRC="$(command -v xmrig)"
echo "[packed] copying $XMRIG_SRC -> ${PACKED_BIN}"
cp "$XMRIG_SRC" "$PACKED_BIN"
chmod +x "$PACKED_BIN"

echo "[packed] packing with upx --best..."
if ! upx --best "$PACKED_BIN" 2>&1 | tee "${EVAL_DIR}/results/${LABEL}.upx.log"; then
  echo "[packed] upx failed to pack this binary (common for some hardened/relocatable" >&2
  echo "[packed] ELF layouts) -- see ${EVAL_DIR}/results/${LABEL}.upx.log for why." >&2
  exit 1
fi

echo "[packed] running packed binary: --bench=${PRESET}"
"$PACKED_BIN" --bench="${PRESET}" --no-color >"${EVAL_DIR}/results/${LABEL}.stdout.log" 2>&1 &
PACKED_PID=$!
echo "[packed] pid=${PACKED_PID}"

python3 "${EVAL_DIR}/results_capture.py" \
  --label "${LABEL}" \
  --pid "${PACKED_PID}" \
  --until-exit \
  --interval "${INTERVAL}" \
  --max-duration 300

# See run_xmrig_test.sh for why this doesn't just `wait`: a throttled
# process can run for many minutes past the capture window.
kill "${PACKED_PID}" 2>/dev/null || true
sleep 1
kill -9 "${PACKED_PID}" 2>/dev/null || true
wait "${PACKED_PID}" 2>/dev/null || true
rm -f "$PACKED_BIN"
echo "[packed] finished — compare ${EVAL_DIR}/results/${LABEL}.csv against"
echo "[packed] evaluation/results/xmrig_ground_truth_*.csv (unpacked) for the same behaviour."
