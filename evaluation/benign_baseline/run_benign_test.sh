#!/usr/bin/env bash
# EDDMC Evaluation — benign-workload false-positive baseline.
#
# A detector that flags every CPU-heavy process isn't credible. This runs
# two genuinely CPU-bound, multi-process/multi-threaded, sustained workloads
# that have nothing to do with cryptomining, and confirms EDDMC does NOT
# raise a detection (or, if it does, records exactly why -- see
# reports/EVALUATION_FINDINGS.md section 4 for a real prior example of this
# surfacing a scorer bug that was then fixed).
#
# Usage: bash run_benign_test.sh [duration_seconds] [trial_label_suffix]
# Requires: eddmc daemon already running

set -euo pipefail

DURATION="${1:-30}"
TRIAL="${2:-}"
OPENSSL_LABEL="benign_openssl${TRIAL:+_${TRIAL}}"
GCC_LABEL="benign_gcc_compile${TRIAL:+_${TRIAL}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(dirname "$SCRIPT_DIR")"
SOCK="/tmp/eddmc.sock"
NPROC="$(nproc)"

if [[ ! -S "$SOCK" ]]; then
  echo "eddmc daemon is not running (no socket at $SOCK)." >&2
  echo "Start it first: sudo python3 daemon/main.py --log-level INFO" >&2
  exit 1
fi

echo "[benign] 1/2: OpenSSL crypto benchmark (multi-process, CPU-bound, ${DURATION}s)"
# -multi forks N worker children that do the actual hashing; the parent just
# waits and aggregates -- filter by comm, not the parent PID, or the capture
# would show near-zero activity while missing the real working processes.
openssl speed -multi "$NPROC" -seconds "$DURATION" sha256 aes-256-cbc \
  >"${EVAL_DIR}/results/${OPENSSL_LABEL}.stdout.log" 2>&1 &
OPENSSL_PID=$!
echo "[benign] openssl pid=${OPENSSL_PID}"

python3 "${EVAL_DIR}/results_capture.py" \
  --label "${OPENSSL_LABEL}" \
  --comm openssl \
  --duration "${DURATION}" \
  --interval 1

wait "${OPENSSL_PID}" 2>/dev/null || true

echo "[benign] 2/2: sustained parallel compilation (gcc -O3, ${DURATION}s)"
SRC="${EVAL_DIR}/results/_benign_bench.c"
python3 - "$SRC" <<'PY'
import sys
path = sys.argv[1]
with open(path, "w") as f:
    f.write("#include <stdio.h>\n")
    for i in range(3000):
        f.write(f"int fn_{i}(int x) {{ return x*{i} + {i}; }}\n")
    f.write("int main(){ return fn_0(1); }\n")
PY

( end=$((SECONDS + DURATION))
  while [[ $SECONDS -lt $end ]]; do
    for i in $(seq 1 "$NPROC"); do
      gcc -O3 -c "$SRC" -o "${EVAL_DIR}/results/_benign_bench_${i}.o" &
    done
    wait
  done
) >"${EVAL_DIR}/results/${GCC_LABEL}.stdout.log" 2>&1 &
GCC_LOOP_PID=$!
echo "[benign] gcc-loop pid=${GCC_LOOP_PID}"

# gcc itself is just a driver that execs cc1 (the actual compiler backend) as
# a fresh child PID per invocation -- same reasoning as openssl above, filter
# by comm ("cc1") rather than trying to track the churning parent/loop PID.
python3 "${EVAL_DIR}/results_capture.py" \
  --label "${GCC_LABEL}" \
  --comm cc1 \
  --duration "${DURATION}" \
  --interval 1

wait "${GCC_LOOP_PID}" 2>/dev/null || true
rm -f "${EVAL_DIR}/results/_benign_bench"*.c "${EVAL_DIR}/results/_benign_bench"*.o
echo "[benign] done. Any non-zero score here is a false-positive finding, not a pass."
