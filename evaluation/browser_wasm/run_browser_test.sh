#!/usr/bin/env bash
# EDDMC Evaluation — in-browser WASM miner-shaped workload (wasmbench /
# NoCoin / MadeWithWasm literature analogue).
#
# One-time setup (downloads Puppeteer's bundled Chromium, ~200MB+ — run this
# yourself when you're ready, it's not run automatically):
#   cd evaluation/browser_wasm && npm install && node build_wasm.js
#
# On arm64 hosts (uname -m == aarch64): Puppeteer's bundled Chromium is
# x64-only. Install a system browser instead and point CHROME_PATH at it:
#   sudo apt install -y chromium-browser
#   export CHROME_PATH=/usr/bin/chromium-browser
#
# Usage: bash run_browser_test.sh [duration_seconds]
# Requires: eddmc daemon already running (sudo python3 daemon/main.py ...)

set -euo pipefail

DURATION="${1:-60}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCK="/tmp/eddmc.sock"

if [[ ! -S "$SOCK" ]]; then
  echo "eddmc daemon is not running (no socket at $SOCK)." >&2
  echo "Start it first: sudo python3 daemon/main.py --log-level INFO" >&2
  exit 1
fi

if [[ ! -d "${SCRIPT_DIR}/node_modules/puppeteer" ]]; then
  echo "Dependencies missing. Run first:" >&2
  echo "  cd ${SCRIPT_DIR} && npm install && node build_wasm.js" >&2
  exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/wasm_source.wasm" ]]; then
  echo "wasm_source.wasm missing. Run: node ${SCRIPT_DIR}/build_wasm.js" >&2
  exit 1
fi

echo "[browser] serving ${SCRIPT_DIR} on http://127.0.0.1:8899 ..."
python3 -m http.server 8899 --directory "${SCRIPT_DIR}" --bind 127.0.0.1 &
SERVER_PID=$!
sleep 1

cd "${SCRIPT_DIR}"
node puppeteer_test.js "${DURATION}"

kill "${SERVER_PID}" 2>/dev/null || true
echo "[browser] test complete."
