#!/usr/bin/env python3
"""
EDDMC Evaluation — Chapter 6 data extraction, Task 7 (v2): mitigation effect,
sampled independently of the daemon's own scan cadence.

Root cause of v1's inconclusive result (evaluation/build_mitigation_effect.py):
confirmed via direct diagnosis (temporary log instrumentation in engine.py,
reverted after use) that the daemon's own `cpu_percent` field only changes
once per REAL `_scan()` cycle, and those cycles run far slower than a 1s
poll interval -- this is not a new bug, it is the same scan-cycle-latency
defect already quantified in `evaluation/results/REPORT.md` §4 (mean 20.2s,
max 34.1s gaps) resurfacing in a new field. Proof: in a fresh capture,
`total_syscalls` (eBPF collector output) climbed every single 1s poll while
`score`/`confidence`/`cpu_percent` (scorer output) stayed frozen for 10
consecutive polls, then jumped together -- collectors run every second,
the scorer does not.

Fix for this measurement specifically (no detection-logic change): sample
this process's real CPU% independently, every second, directly via psutil
from this script -- not through the daemon at all -- while polling the
daemon's own /api/processes only for its current confidence/mitigation
tier (which, even though it updates on the same slow cadence, still
correctly reflects the last real scan's decision at any given moment).
"""

import argparse
import http.client
import json
import socket
import subprocess
import sys
import time

import psutil


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


def _daemon_state_for_comm(sock_path, comm_substr):
    conn = _UnixHTTPConnection(sock_path)
    conn.request("GET", "/api/processes")
    resp = conn.getresponse()
    procs = json.loads(resp.read())
    conn.close()
    matches = [p for p in procs if comm_substr in p.get("comm", "")]
    if not matches:
        return None
    return max(matches, key=lambda p: p.get("score", 0))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sock", default="/tmp/eddmc.sock")
    ap.add_argument("--xmrig-args", default="--bench=1M --randomx-mode=light -t 1 --no-color",
                    help="xmrig args -- kept light by default given this host's limited free memory")
    ap.add_argument("--duration", type=int, default=90)
    ap.add_argument("--out", default="evaluation/results/mitigation_effect_v2.csv")
    args = ap.parse_args()

    xmrig_argv = ["/usr/bin/xmrig"] + args.xmrig_args.split()
    proc = subprocess.Popen(xmrig_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ps_proc = psutil.Process(proc.pid)
    ps_proc.cpu_percent(interval=None)  # discard the mandatory first-call 0.0 artifact

    rows = []
    t0 = time.time()
    print(f"[measure_v2] xmrig pid={proc.pid}, sampling for {args.duration}s", file=sys.stderr)
    try:
        while time.time() - t0 < args.duration:
            time.sleep(1)
            elapsed = time.time() - t0
            try:
                external_cpu = ps_proc.cpu_percent(interval=None)
            except psutil.NoSuchProcess:
                break
            state = _daemon_state_for_comm(args.sock, "xmrig")
            row = {
                "elapsed_s": round(elapsed, 1),
                "external_cpu_percent": external_cpu,
                "daemon_confidence": state["confidence"] if state else "",
                "daemon_mitigation": state["mitigation"] if state else "",
                "daemon_score": state["score"] if state else "",
            }
            rows.append(row)
            print(f"[measure_v2] t={row['elapsed_s']:.1f}s cpu={external_cpu:.1f}% "
                  f"conf={row['daemon_confidence']} mit={row['daemon_mitigation']}", file=sys.stderr)
    finally:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except Exception:
            pass

    with open(args.out, "w") as f:
        f.write("elapsed_s,external_cpu_percent,daemon_confidence,daemon_mitigation,daemon_score\n")
        for r in rows:
            f.write(f"{r['elapsed_s']},{r['external_cpu_percent']},{r['daemon_confidence']},"
                    f"{r['daemon_mitigation']},{r['daemon_score']}\n")
    print(f"[measure_v2] {len(rows)} rows written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
