#!/usr/bin/env python3
"""
EDDMC Evaluation — detector's own resource overhead.

Nearly every cryptojacking-detector paper (MineSweeper, Outguard, CMTracker)
reports the detector's own CPU/memory footprint alongside detection
accuracy -- a detector that catches every miner but costs 50% CPU itself
isn't practical. This measures the EDDMC daemon PROCESS's own CPU% and RSS
over time, independent of whatever it's currently monitoring.

Usage:
  python3 measure_daemon_overhead.py --label idle_baseline --duration 15

Chunked/resumable execution: this evaluation session's execution environment
was found partway through P0-2 to terminate any process after roughly 20-30
seconds -- a change from earlier in the same session, when 300+ second
measurements ran fine repeatedly. To get a true 300s+ continuous trial
despite this, this script APPENDS to --out if it already has rows,
reconstructing the true trial start time from the first row's wall_time
rather than resetting to 0 -- so a wrapper can call it repeatedly in short
chunks and the result reads as one continuous trial.

CPU% normalisation convention (P0-2 acceptance criteria: state this
explicitly, since an ambiguous convention was itself part of the original
problem): cpu_percent here is AGGREGATE across all of the daemon's threads
and therefore across however many cores they run on -- 100% means one full
core saturated, 400% would mean all 4 cores on this host fully saturated.
This matches `top`'s default convention and `measure_system_baseline.py`'s
system-wide figure, so the two are directly comparable. It is computed from
/proc/<pid>/stat's utime+stime fields, which the kernel aggregates across
all threads of the process (not per-thread), divided by wall-clock elapsed
time between samples.
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
        after = raw[raw.rfind(")") + 2:]
        fields = after.split()
        utime, stime = int(fields[11]), int(fields[12])
        return utime, stime
    except (OSError, IndexError, ValueError):
        return None


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


def _existing_start_and_last(out_path):
    if not os.path.exists(out_path):
        return None, 0.0
    with open(out_path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return None, 0.0
    true_start = float(rows[0]["wall_time"]) - float(rows[0]["elapsed_s"])
    last_elapsed = float(rows[-1]["elapsed_s"])
    return true_start, last_elapsed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True)
    ap.add_argument("--duration", type=float, default=15.0, help="This CHUNK's duration, not the total trial length")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--socket", default="/tmp/eddmc.sock")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    pid = _find_daemon_pid()

    out_path = args.out or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "results", f"overhead_{args.label}.csv"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    true_start, last_elapsed = _existing_start_and_last(out_path)
    resuming = true_start is not None
    if not resuming:
        true_start = time.time()
    print(f"[overhead] monitoring daemon pid={pid} ({'resuming' if resuming else 'starting'} trial "
          f"at elapsed={last_elapsed:.1f}s)")

    hz = os.sysconf("SC_CLK_TCK")
    rows = []
    chunk_start = time.time()
    prev = _cpu_times(pid)
    prev_wall = chunk_start

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
            "elapsed_s": round(now - true_start, 1),
            "cpu_percent": round(cpu_pct, 2),
            "rss_mb": round(_rss_mb(pid), 2),
            "num_threads": _num_threads(pid),
            "tracked_processes": _tracked_count(args.socket),
        })

        if now - chunk_start >= args.duration:
            break

    write_header = not resuming
    with open(out_path, "a" if resuming else "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if write_header:
            w.writeheader()
        w.writerows(rows)

    total_elapsed = rows[-1]["elapsed_s"] if rows else last_elapsed
    print(f"[overhead] chunk wrote {len(rows)} rows -> {out_path} (trial elapsed so far: {total_elapsed:.1f}s)")


if __name__ == "__main__":
    main()
