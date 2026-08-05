#!/usr/bin/env bash
# EDDMC live-demo launcher.
#
# Starts, in order: the daemon (sudo, backgrounded), a harmless local
# mock stratum-pool listener, xmrig pointed at that mock pool, then the
# Electron UI in the foreground (Ctrl-C to stop watching it -- the
# daemon/pool/xmrig keep running in the background; use demo_stop.sh to
# clean those up afterwards).
#
# Usage: bash scripts/demo_start.sh

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[demo]${NC} $*"; }
warn()  { echo -e "${YELLOW}[demo]${NC} $*"; }
error() { echo -e "${RED}[demo]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

LOG_DIR=/tmp/eddmc_demo_logs
mkdir -p "$LOG_DIR"

# ── 1. Daemon ────────────────────────────────────────────────────────────
if pgrep -f "daemon/main.py" >/dev/null 2>&1; then
  info "Daemon already running -- leaving it as-is."
else
  info "Starting daemon (will prompt for your sudo password)..."
  sudo -v || { error "sudo authentication failed -- aborting."; exit 1; }
  sudo nohup /usr/bin/python3 "$REPO_DIR/daemon/main.py" --log-level INFO \
    > "$LOG_DIR/daemon.log" 2>&1 &
  disown

  info "Waiting for /tmp/eddmc.sock..."
  for _ in $(seq 1 30); do
    [[ -S /tmp/eddmc.sock ]] && break
    sleep 1
  done
  if [[ -S /tmp/eddmc.sock ]]; then
    info "Daemon up ($(pgrep -f 'daemon/main.py' | tr '\n' ' '))."
  else
    error "Daemon did not come up within 30s -- check $LOG_DIR/daemon.log"
    exit 1
  fi
fi

# ── 2. Mock mining-pool listener (local-only, harmless) ─────────────────
if pgrep -f "mock_pool_listener.py" >/dev/null 2>&1; then
  info "Mock pool listener already running."
else
  info "Starting mock pool listener..."
  python3 "$REPO_DIR/evaluation/network_pool_blocklist/mock_pool_listener.py" --hold 5 \
    > "$LOG_DIR/mock_pool.log" 2>&1 &
  disown
  sleep 1
fi

# ── 3. xmrig, pointed at the mock pool ───────────────────────────────────
if pgrep -x xmrig >/dev/null 2>&1; then
  info "xmrig already running."
else
  info "Starting xmrig..."
  /usr/bin/xmrig --randomx-mode=light --no-color -o 127.0.0.1:3333 -u mockwallet -p x \
    > "$LOG_DIR/xmrig.log" 2>&1 &
  disown
fi

info "Workload is live. Expect MEDIUM around ~25s, HIGH/BLOCK around ~40s (see reports/FINAL_EVALUATION_V2.md)."
info "Logs: $LOG_DIR/"

# ── 4. UI (foreground -- Ctrl-C just closes the window/script, background ──
#        processes above keep running; use demo_stop.sh to tear them down) ──
info "Launching UI (npm start)..."
cd "$REPO_DIR/client-app"
npm start
