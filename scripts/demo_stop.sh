#!/usr/bin/env bash
# Tears down everything scripts/demo_start.sh launched: xmrig, the mock
# pool listener, the Electron UI, and (unless --keep-daemon is passed)
# the daemon itself.
#
# Usage: bash scripts/demo_stop.sh [--keep-daemon]

KEEP_DAEMON=0
[[ "${1:-}" == "--keep-daemon" ]] && KEEP_DAEMON=1

GREEN='\033[0;32m'; NC='\033[0m'
info() { echo -e "${GREEN}[demo]${NC} $*"; }

pkill -x xmrig 2>/dev/null && info "Stopped xmrig." || info "xmrig was not running."
pkill -f "mock_pool_listener.py" 2>/dev/null && info "Stopped mock pool listener." || info "Mock pool listener was not running."
pkill -f "electron ." 2>/dev/null && info "Stopped Electron UI." || info "Electron UI was not running."

if [[ $KEEP_DAEMON -eq 1 ]]; then
  info "Leaving daemon running (--keep-daemon)."
else
  if pgrep -f "daemon/main.py" >/dev/null 2>&1; then
    sudo pkill -f "daemon/main.py" && info "Stopped daemon."
  else
    info "Daemon was not running."
  fi
fi
