#!/usr/bin/env bash
# Simulate a CPU-bound multi-threaded workload to trigger EDDMC detection.
# This is NOT real mining — it just stress-tests the detector with a
# futex-heavy, CPU-saturating process similar in behaviour to xmrig.
#
# Usage: bash scripts/test_miner.sh [threads]

THREADS=${1:-$(nproc)}
echo "[TEST] Launching synthetic miner workload — $THREADS threads"
echo "[TEST] PID $$  (watch with: eddmc watch)"
echo "[TEST] Ctrl-C to stop"

# stress-ng simulates cryptominer behaviour: CPU-bound, many threads,
# futex synchronisation, minimal I/O.
if command -v stress-ng &>/dev/null; then
  stress-ng --cpu "$THREADS" --cpu-method matrixprod --timeout 120s &
  STRESS_PID=$!
  echo "[TEST] stress-ng pid=$STRESS_PID"
  wait $STRESS_PID
else
  echo "[TEST] stress-ng not found — running pure Python busy loop"
  python3 - <<'PY'
import threading, time, hashlib, os

def worker():
    data = os.urandom(64)
    while True:
        for _ in range(10000):
            hashlib.sha256(data).digest()

threads = [threading.Thread(target=worker, daemon=True) for _ in range(os.cpu_count() or 4)]
for t in threads: t.start()
try:
    time.sleep(120)
except KeyboardInterrupt:
    pass
PY
fi
