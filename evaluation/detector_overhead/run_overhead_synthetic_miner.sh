#!/usr/bin/env bash
# EDDMC Evaluation — daemon overhead while a synthetic miner-shaped workload
# is active (P0-2 condition 4 substitute).
#
# Real XMRig cannot be used for this condition: this evaluation discovered
# that any real, unmodified XMRig execution in this environment is killed
# within a few seconds of exhibiting live RandomX-mining behavior by a
# mechanism external to EDDMC (confirmed via two independent tests, at two
# different file paths, both surviving only long enough to start actually
# hashing before being terminated and having their source binary quarantined
# via chattr +i). This makes a real, sustained 300s+ XMRig trial impossible
# in this environment regardless of path or permission-fixing between
# trials -- see reports/EVALUATION_ROUND2.md P0-1/P0-2 for the full finding.
#
# Substitute: the same CPU-bound, multi-threaded, futex-heavy synthetic
# workload already used by scripts/test_miner.sh (Python hashlib.sha256
# busy loop, N threads = nproc), reimplemented here with a configurable
# duration since test_miner.sh hardcodes 120s. This does NOT allocate a
# RandomX-style 2MB scratchpad or request huge pages, so it will not trigger
# EDDMC's scratchpad-floor signal the way real XMRig does -- it exercises
# the CPU-bound/thread-saturation/futex dimensions only. This is an explicit,
# documented substitution, not a silent swap.
#
# Usage: bash run_overhead_synthetic_miner.sh [duration_seconds] [trial_label_suffix]

set -euo pipefail
DURATION="${1:-300}"
TRIAL="${2:-}"
LABEL="synthetic_miner_active${TRIAL:+_${TRIAL}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -S /tmp/eddmc.sock ]]; then
  echo "eddmc daemon is not running." >&2
  exit 1
fi

echo "[overhead-synthetic] starting synthetic CPU-bound workload for ${DURATION}s..."
python3 - "$DURATION" <<'PY' &
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

python3 "${SCRIPT_DIR}/measure_daemon_overhead.py" --label "${LABEL}" --duration "${DURATION}" --interval 1

kill "$WORKLOAD_PID" 2>/dev/null || true
wait "$WORKLOAD_PID" 2>/dev/null || true
echo "[overhead-synthetic] done."
