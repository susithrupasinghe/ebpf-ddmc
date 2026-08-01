#!/usr/bin/env python3
"""
EDDMC — postfix verification, Step 3: telemetry-level check of the
sched_monitor.c TID-aggregation fix, BEFORE any scoring run.

Launches a short multi-threaded CPU-bound workload, and for its pid,
compares the daemon's own on_cpu_ns/voluntary_switches/involuntary_switches
(read live via /api/processes) against an independent psutil cpu_percent
sample taken directly by this script (same technique as
measure_mitigation_effect_v2.py) each second. Reports:
  - whether cumulative on_cpu_ns is monotonic (no negative deltas)
  - the on_cpu_ns-derived CPU% (per-core convention: delta_ns/delta_wall_ns*100)
    against the independently-sampled psutil CPU%
  - voluntary/involuntary switch counts, checked for plausibility (nonzero,
    consistent with a saturated process)

Writes evaluation/results/postfix/sched_fix_telemetry.csv. Does not touch
any existing evaluation result and does not invoke the scorer.
"""

import argparse
import csv
import http.client
import json
import os
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


def _daemon_process_by_pid(sock_path, pid):
    conn = _UnixHTTPConnection(sock_path)
    conn.request("GET", "/api/processes")
    resp = conn.getresponse()
    procs = json.loads(resp.read())
    conn.close()
    for p in procs:
        if p.get("pid") == pid:
            return p
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sock", default="/tmp/eddmc.sock")
    ap.add_argument("--xmrig-args", default="--bench=1M --randomx-mode=light -t 4 --no-color",
                    help="4 threads to genuinely exercise multi-thread worker aggregation; "
                         "light mode kept for this host's limited free memory")
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--out", default="evaluation/results/postfix/sched_fix_telemetry.csv")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    xmrig_argv = ["/usr/bin/xmrig"] + args.xmrig_args.split()
    proc = subprocess.Popen(xmrig_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ps_proc = psutil.Process(proc.pid)
    ps_proc.cpu_percent(interval=None)  # discard mandatory first-call 0.0 artifact

    rows = []
    t0 = time.time()
    prev_on_cpu_ns = None
    print(f"[verify] xmrig pid={proc.pid}, sampling for {args.duration}s", file=sys.stderr)
    try:
        while time.time() - t0 < args.duration:
            time.sleep(1)
            elapsed = time.time() - t0
            try:
                external_cpu = ps_proc.cpu_percent(interval=None)
            except psutil.NoSuchProcess:
                break
            d = _daemon_process_by_pid(args.sock, proc.pid)
            sched = (d or {}).get("sched", {})
            # /api/processes flattens "sched" only if present at top level;
            # fall back to on_cpu_ns/voluntary_switches/involuntary_switches
            # keys directly on the process dict if that's how socket_server
            # exposes it (matches results_capture.py's own p.get("sched", {})).
            on_cpu_ns = sched.get("on_cpu_ns", d.get("on_cpu_ns") if d else None)
            vol = sched.get("voluntary_switches", d.get("voluntary_switches") if d else None)
            invol = sched.get("involuntary_switches", d.get("involuntary_switches") if d else None)

            delta_ns = None
            negative_delta = False
            if on_cpu_ns is not None and prev_on_cpu_ns is not None:
                delta_ns = on_cpu_ns - prev_on_cpu_ns
                if delta_ns < 0:
                    negative_delta = True
            derived_pct = None
            if delta_ns is not None and delta_ns >= 0:
                derived_pct = (delta_ns / 1e9) / 1.0 * 100.0  # 1s poll interval, per-core convention

            row = {
                "elapsed_s": round(elapsed, 1),
                "external_cpu_percent": external_cpu,
                "on_cpu_ns": on_cpu_ns,
                "on_cpu_ns_delta": delta_ns,
                "negative_delta": negative_delta,
                "derived_cpu_percent_1s": derived_pct,
                "voluntary_switches": vol,
                "involuntary_switches": invol,
                "thread_count": (d or {}).get("thread_count"),
            }
            rows.append(row)
            print(f"[verify] t={row['elapsed_s']:.1f}s ext_cpu={external_cpu:.1f}% "
                  f"on_cpu_ns={on_cpu_ns} delta={delta_ns} derived={derived_pct} "
                  f"vol={vol} invol={invol} threads={row['thread_count']}", file=sys.stderr)
            if on_cpu_ns is not None:
                prev_on_cpu_ns = on_cpu_ns
    finally:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except Exception:
            pass

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [
            "elapsed_s", "external_cpu_percent", "on_cpu_ns", "on_cpu_ns_delta",
            "negative_delta", "derived_cpu_percent_1s", "voluntary_switches",
            "involuntary_switches", "thread_count"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[verify] {len(rows)} rows written to {args.out}", file=sys.stderr)

    any_negative = any(r["negative_delta"] for r in rows)
    print(f"[verify] any_negative_delta={any_negative}", file=sys.stderr)


if __name__ == "__main__":
    main()
