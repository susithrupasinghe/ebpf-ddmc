#!/usr/bin/env bash
# EDDMC Installation Script
# Run as root: sudo bash scripts/install.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root (sudo bash $0)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

info "EDDMC installation starting…"
info "Repo: $REPO_DIR"

# ── 1. Kernel checks ────────────────────────────────────────────────────────
info "Checking kernel eBPF support…"
KVER=$(uname -r)
info "Kernel: $KVER"

for flag in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_EVENTS; do
  val=$(grep "^$flag=" "/boot/config-$KVER" 2>/dev/null || true)
  if [[ "$val" != "${flag}=y" ]]; then
    warn "$flag not set — eBPF may not work correctly"
  fi
done

if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  warn "BTF vmlinux not found — CO-RE features unavailable"
else
  info "BTF support: OK"
fi

# ── 2. System dependencies ─────────────────────────────────────────────────
info "Installing system packages…"
apt-get update -qq
apt-get install -y -qq \
  python3 python3-pip python3-venv python3-full \
  python3-psutil python3-yaml \
  bpfcc-tools python3-bpfcc \
  libbpf-dev \
  bpftool \
  iptables \
  libcap2-bin \
  psmisc

# ── 3. Python dependencies ─────────────────────────────────────────────────
# Try apt packages first (preferred on Ubuntu/Debian — avoids PEP 668 issues)
info "Installing Python dependencies via apt…"
apt-get install -y -qq python3-psutil python3-yaml 2>/dev/null || true

# Verify both packages are importable; fall back to venv if not
PYTHON=$(command -v python3)
if ! "$PYTHON" -c "import psutil, yaml" 2>/dev/null; then
  info "apt packages not sufficient — creating venv…"
  apt-get install -y -qq python3-venv python3-full 2>/dev/null || true
  VENV_DIR="$REPO_DIR/.venv"
  python3 -m venv --system-site-packages "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -q psutil PyYAML
  PYTHON="$VENV_DIR/bin/python3"
else
  VENV_DIR=""
  info "Python dependencies satisfied via system packages"
fi

info "Python: $($PYTHON --version)"

# ── 4. Log directory ───────────────────────────────────────────────────────
info "Creating log directory…"
mkdir -p /var/log/eddmc
chmod 750 /var/log/eddmc

# ── 5. cgroup v2 check ─────────────────────────────────────────────────────
if mount | grep -q "cgroup2"; then
  info "cgroup v2: mounted"
else
  warn "cgroup v2 not mounted — CPU throttling will not work"
  warn "Add 'systemd.unified_cgroup_hierarchy=1' to kernel cmdline"
fi

# ── 6. Systemd service ─────────────────────────────────────────────────────
info "Installing systemd service…"
cat > /etc/systemd/system/eddmc.service << EOF
[Unit]
Description=EDDMC - eBPF CPU Cryptojacking Detection Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$PYTHON $REPO_DIR/daemon/main.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=eddmc

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
info "Systemd service installed (eddmc.service)"
info "Start with: systemctl start eddmc"
info "Enable at boot: systemctl enable eddmc"

# ── 7. CLI symlink ─────────────────────────────────────────────────────────
cat > /usr/local/bin/eddmc << SCRIPT
#!$PYTHON
import sys
sys.path.insert(0, '$REPO_DIR')
from daemon.cli.commands import main
main()
SCRIPT
chmod +x /usr/local/bin/eddmc
info "CLI installed: /usr/local/bin/eddmc"

# ── 8. Node / Electron (client-app) ────────────────────────────────────────
if command -v npm &>/dev/null; then
  info "Installing Electron client-app dependencies…"
  cd "$REPO_DIR/client-app" && npm install --silent
  info "client-app ready. Run with: cd client-app && npm start"
else
  warn "npm not found — skipping Electron client-app setup"
  warn "Install Node.js then run: cd client-app && npm install"
fi

echo ""
info "EDDMC installation complete!"
echo ""
echo "  Start daemon:   sudo systemctl start eddmc"
echo "  Watch live:     eddmc watch"
echo "  View alerts:    eddmc alerts"
echo "  Launch UI:      cd client-app && npm start"
echo ""
