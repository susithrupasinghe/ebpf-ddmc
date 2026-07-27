#!/usr/bin/env python3
"""
EDDMC Evaluation — shared results-capture instrument.

Polls the running eddmc daemon over its Unix socket HTTP API
(/api/processes, /api/alerts) at a fixed interval and appends one CSV row
per tracked process per tick. Every test track in evaluation/ (xmrig
ground truth, network pool-hits, browser WASM miner, and any future
malware-corpus run) writes through this same script so all results land
in a comparable format for the thesis results section.

Usage:
  # Fixed duration, capture every tracked process:
  python3 results_capture.py --label xmrig_ground_truth --duration 60

  # Follow one PID until it exits (or a safety cap is hit):
  python3 results_capture.py --label xmrig_ground_truth --pid 12345 --until-exit

Output: evaluation/results/<label>.csv (override with --out), plus a
one-line summary printed to stdout (peak score, tier reached, time to
first alert-worthy score) that you can paste straight into a results table.
"""

import argparse
import csv
import http.client
import json
import os
import socket
import sys
import time

FIELDS = [
    "wall_time", "elapsed_s", "pid", "comm", "score", "confidence",
    "mitigation", "ticks", "total_syscalls", "futex", "mmap", "mprotect",
    "clone", "nanosleep", "read", "write", "socket_calls", "connect",
    "send", "recv", "brk", "thread_count", "on_cpu_ns",
    "voluntary_switches", "involuntary_switches", "total_connections",
    "mining_pool_hits", "total_mmap_bytes", "scratchpad_allocs",
    "huge_page_requests", "large_alloc_count", "mprotect_large", "reasons",
]

CONFIDENCE_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _get(sock_path: str, path: str):
    c = http.client.HTTPConnection("localhost")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    c.sock = s
    c.request("GET", path)
    r = c.getresponse()
    return json.loads(r.read())


def _flatten(p: dict, wall_time: float, elapsed: float) -> dict:
    sc = p.get("syscall_counts", {})
    sd = p.get("sched", {})
    nt = p.get("net", {})
    mm = p.get("mem", {})
    return {
        "wall_time": round(wall_time, 3),
        "elapsed_s": round(elapsed, 1),
        "pid": p.get("pid"),
        "comm": p.get("comm"),
        "score": p.get("score", 0.0),
        "confidence": p.get("confidence", "NONE"),
        "mitigation": p.get("mitigation", "NONE"),
        "ticks": p.get("ticks", 0),
        "total_syscalls": sc.get("total", 0),
        "futex": sc.get("futex", 0),
        "mmap": sc.get("mmap", 0),
        "mprotect": sc.get("mprotect", 0),
        "clone": sc.get("clone", 0),
        "nanosleep": sc.get("nanosleep", 0),
        "read": sc.get("read", 0),
        "write": sc.get("write", 0),
        "socket_calls": sc.get("socket", 0),
        "connect": sc.get("connect", 0),
        "send": sc.get("send", 0),
        "recv": sc.get("recv", 0),
        "brk": sc.get("brk", 0),
        "thread_count": sd.get("thread_count", 0),
        "on_cpu_ns": sd.get("on_cpu_ns", 0),
        "voluntary_switches": sd.get("voluntary_switches", 0),
        "involuntary_switches": sd.get("involuntary_switches", 0),
        "total_connections": nt.get("total_connections", 0),
        "mining_pool_hits": nt.get("mining_pool_hits", 0),
        "total_mmap_bytes": mm.get("total_mmap_bytes", 0),
        "scratchpad_allocs": mm.get("scratchpad_allocs", 0),
        "huge_page_requests": mm.get("huge_page_requests", 0),
        "large_alloc_count": mm.get("large_alloc_count", 0),
        "mprotect_large": mm.get("mprotect_large", 0),
        "reasons": "; ".join(p.get("reasons", [])),
    }


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True, help="Test-run label; also the default output filename")
    ap.add_argument("--socket", default="/tmp/eddmc.sock", help="eddmc IPC socket path")
    ap.add_argument("--interval", type=float, default=2.0, help="Poll interval in seconds")
    ap.add_argument("--duration", type=float, default=60.0, help="Fixed capture duration in seconds (ignored with --until-exit)")
    ap.add_argument("--pid", type=int, default=None, help="Only record rows for this PID")
    ap.add_argument("--comm", default=None, help="Only record rows whose comm contains this substring "
                     "(use for workloads that fork worker children under different PIDs, e.g. "
                     "'openssl speed -multi' or a gcc/cc1 compile loop -- a single parent PID would "
                     "miss the actual working processes entirely)")
    ap.add_argument("--until-exit", action="store_true", help="Run until --pid exits instead of a fixed duration (requires --pid)")
    ap.add_argument("--max-duration", type=float, default=600.0, help="Safety cap when using --until-exit")
    ap.add_argument("--out", default=None, help="Output CSV path (default evaluation/results/<label>.csv)")
    args = ap.parse_args()

    if args.until_exit and args.pid is None:
        ap.error("--until-exit requires --pid")

    if not os.path.exists(args.socket):
        print(f"eddmc socket not found at {args.socket} — is the daemon running (sudo)?", file=sys.stderr)
        sys.exit(1)

    out_path = args.out or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "results", f"{args.label}.csv"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    start = time.time()
    rows = []
    print(f"[capture] label={args.label} -> {out_path}")

    while True:
        elapsed = time.time() - start
        try:
            procs = _get(args.socket, "/api/processes")
        except Exception as exc:
            print(f"[capture] poll failed: {exc}", file=sys.stderr)
            procs = []

        wall_time = time.time()
        for p in procs:
            if args.pid is not None and p.get("pid") != args.pid:
                continue
            if args.comm and args.comm not in p.get("comm", ""):
                continue
            rows.append(_flatten(p, wall_time, elapsed))

        if args.until_exit:
            if not _pid_alive(args.pid) or elapsed >= args.max_duration:
                break
        else:
            if elapsed >= args.duration:
                break

        time.sleep(args.interval)

    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    if not rows:
        print("[capture] no rows recorded — was the target process actually tracked by eddmc?")
        return

    peak = max(rows, key=lambda r: r["score"])
    first_alert = next((r for r in rows if CONFIDENCE_RANK.get(r["confidence"], 0) >= CONFIDENCE_RANK["LOW"]), None)

    print(f"[capture] {len(rows)} rows written to {out_path}")
    print(f"[summary] peak_score={peak['score']:.1f} peak_confidence={peak['confidence']} "
          f"peak_mitigation={peak['mitigation']} pid={peak['pid']} comm={peak['comm']}")
    if first_alert:
        print(f"[summary] time_to_first_alert_tier={first_alert['elapsed_s']:.1f}s "
              f"(confidence={first_alert['confidence']})")
    else:
        print("[summary] never reached an alert-worthy confidence tier during capture")


if __name__ == "__main__":
    main()
