#!/usr/bin/env bash
# Quick launcher for the EDDMC daemon.
# Usage: sudo bash scripts/run_daemon.sh [--dry-run] [--log-level DEBUG]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

if [[ $EUID -ne 0 ]]; then
  echo "EDDMC requires root. Run: sudo bash $0 $*"
  exit 1
fi

# Always use the system python3 at a fixed path so both root and user
# resolve the same interpreter and site-packages.
PYTHON=/usr/bin/python3

# Auto-install missing deps via apt (no pip, no PEP 668 issues)
if ! "$PYTHON" -c "import psutil" 2>/dev/null; then
  echo "[setup] Installing python3-psutil via apt…"
  apt-get install -y -qq python3-psutil
fi

if ! "$PYTHON" -c "import yaml" 2>/dev/null; then
  echo "[setup] Installing python3-yaml via apt…"
  apt-get install -y -qq python3-yaml
fi

exec "$PYTHON" "$REPO_DIR/daemon/main.py" "$@"
