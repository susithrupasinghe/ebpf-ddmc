#!/usr/bin/env python3
"""
EDDMC Evaluation — detector's own resource overhead.

Nearly every cryptojacking-detector paper (MineSweeper, Outguard, CMTracker)
reports the detector's own CPU/memory footprint alongside detection
accuracy -- a detector that catches every miner but costs 50% CPU itself
isn't practical. This measures the EDDMC daemon PROCESS's own CPU% and RSS
over time, independent of whatever it's currently monitoring.

Usage:
  python3 measure_daemon_overhead.py --label idle_baseline --duration 60
  python3 measure_daemon_overhead.py --label under_load --duration 60

Run once with nothing else happening (idle baseline) and once while a test
workload (e.g. xmrig_ground_truth) runs concurrently, then compare the two
CSVs' mean/peak cpu_percent and rss_mb.
"""

import argparse
import csv
import os
import re
import subprocess
import sys
import time

FIELDS = ["wall_time", "elapsed_s", "cpu_percent", "rss_mb", "num_threads", "tracked_processes"]


def _comm(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return ""


def _find_daemon_pid() -> int:
    """
    `pgrep -f daemon/main.py` also matches the `sudo` wrapper process(es) in
    the chain (sudo -> sudo -> python3), which have negligible RSS of their
    own -- picking the first match can silently measure the wrapper instead
    of the real interpreter. Filter to the actual python3 process, and if
    more than one somehow matches (e.g. a stale process from a prior run),
    take the one with the largest RSS.
    """
    out = subprocess.run(
        ["pgrep", "-f", "daemon/main.py"], capture_output=True, text=True
    ).stdout.strip()
    candidates = [int(p) for p in out.splitlines() if p.strip()]
    python_pids = [p for p in candidates if _comm(p) == "python3"]
    if not python_pids:
        print("Could not find a running 'daemon/main.py' python3 process "
              f"(pgrep matched: {candidates}).", file=sys.stderr)
        sys.exit(1)
    return max(python_pids, key=_rss_mb)


def _cpu_times(pid: int):
    """(utime, stime) in clock ticks from /proc/<pid>/stat, or None if unreadable."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            raw = f.read()
        # comm field can contain spaces/parens -- split after the last ')'
        after = raw[raw.rfind(")") + 2:]
        fields = after.split()
        utime, stime = int(fields[11]), int(fields[12])
        return utime, stime
    except (OSError, IndexError, ValueError):
        return None


def _rss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    kb = int(re.search(r"(\d+)", line).group(1))
                    return kb / 1024.0
    except (OSError, AttributeError):
        pass
    return 0.0


def _num_threads(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/task"))
    except OSError:
        return 0


def _tracked_count(socket_path: str) -> int:
    try:
        import http.client, socket, json
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(socket_path)
        c = http.client.HTTPConnection("localhost")
        c.sock = s
        c.request("GET", "/api/status")
        r = c.getresponse()
        return json.loads(r.read()).get("tracked", 0)
    except Exception:
        return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--socket", default="/tmp/eddmc.sock")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    pid = _find_daemon_pid()
    print(f"[overhead] monitoring daemon pid={pid}")

    out_path = args.out or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "results", f"overhead_{args.label}.csv"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    hz = os.sysconf("SC_CLK_TCK")
    rows = []
    start = time.time()
    prev = _cpu_times(pid)
    prev_wall = start

    while True:
        time.sleep(args.interval)
        now = time.time()
        cur = _cpu_times(pid)
        cpu_pct = 0.0
        if prev is not None and cur is not None:
            dt_ticks = (cur[0] - prev[0]) + (cur[1] - prev[1])
            dt_wall = now - prev_wall
            if dt_wall > 0:
                cpu_pct = 100.0 * (dt_ticks / hz) / dt_wall
        prev, prev_wall = cur, now

        rows.append({
            "wall_time": round(now, 3),
            "elapsed_s": round(now - start, 1),
            "cpu_percent": round(cpu_pct, 2),
            "rss_mb": round(_rss_mb(pid), 2),
            "num_threads": _num_threads(pid),
            "tracked_processes": _tracked_count(args.socket),
        })

        if now - start >= args.duration:
            break

    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    cpu_vals = [r["cpu_percent"] for r in rows[1:]]  # skip first sample (no prior delta)
    rss_vals = [r["rss_mb"] for r in rows]
    print(f"[overhead] {len(rows)} rows written to {out_path}")
    if cpu_vals:
        print(f"[summary] cpu_percent: mean={sum(cpu_vals)/len(cpu_vals):.2f} peak={max(cpu_vals):.2f}")
    print(f"[summary] rss_mb: mean={sum(rss_vals)/len(rss_vals):.1f} peak={max(rss_vals):.1f}")


if __name__ == "__main__":
    main()
