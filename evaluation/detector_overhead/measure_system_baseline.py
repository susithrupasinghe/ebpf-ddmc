#!/usr/bin/env python3
"""
EDDMC Evaluation — system-wide CPU baseline with the daemon STOPPED (P0-2
condition 1). Reads /proc/stat deltas system-wide, independent of any
specific process, so it's meaningful even though the daemon isn't running
to be queried via its own API.

CPU% convention: aggregate across all cores (100% = one core fully busy,
consistent with `top`'s default and with measure_daemon_overhead.py's
convention for the other 3 conditions -- stated explicitly here per P0-2's
acceptance criteria).

Chunked/resumable execution: this evaluation session's execution environment
was found partway through P0-2 to terminate any process (backgrounded,
foregrounded, or nohup+disown-detached) after roughly 20-30 seconds -- a
change from earlier in the same session, when 300+ second measurements ran
fine repeatedly. To get a true 300s+ continuous trial despite this, this
script APPENDS to --out if it already has rows, reconstructing the true
trial start time from the first row's wall_time rather than resetting to 0
-- so a wrapper can call it repeatedly in short chunks and the result reads
as one continuous trial. See run_chunked_baseline.sh, which drives this.

Usage:
  # Single-shot (works fine for durations under the ~20-30s ceiling):
  python3 measure_system_baseline.py --label baseline_t1 --duration 15

  # Resumed (second+ call with the same --label continues, does not restart):
  python3 measure_system_baseline.py --label baseline_t1 --duration 15
"""
import argparse
import csv
import os
import time

FIELDS = ["wall_time", "elapsed_s", "cpu_percent"]


def _read_proc_stat():
    with open("/proc/stat") as f:
        line = f.readline()
    parts = [int(x) for x in line.split()[1:]]
    idle = parts[3] + parts[4]  # idle + iowait
    total = sum(parts)
    return idle, total


def _existing_start_and_last(out_path):
    """Return (true_start_wall_time, last_elapsed_s) from an existing CSV,
    or (None, 0.0) if the file doesn't exist yet / is empty."""
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
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    out_path = args.out or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "results", f"overhead_{args.label}.csv"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    true_start, last_elapsed = _existing_start_and_last(out_path)
    resuming = true_start is not None
    if not resuming:
        true_start = time.time()

    ncpu = os.cpu_count()
    rows = []
    chunk_start = time.time()
    prev_idle, prev_total = _read_proc_stat()

    while True:
        time.sleep(args.interval)
        now = time.time()
        idle, total = _read_proc_stat()
        d_idle = idle - prev_idle
        d_total = total - prev_total
        cpu_pct = 100.0 * ncpu * (1.0 - d_idle / d_total) if d_total > 0 else 0.0
        prev_idle, prev_total = idle, total
        rows.append({"wall_time": round(now, 3), "elapsed_s": round(now - true_start, 1),
                     "cpu_percent": round(cpu_pct, 2)})
        if now - chunk_start >= args.duration:
            break

    write_header = not resuming
    with open(out_path, "a" if resuming else "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if write_header:
            w.writeheader()
        w.writerows(rows)

    total_elapsed = rows[-1]["elapsed_s"] if rows else last_elapsed
    print(f"[baseline] chunk wrote {len(rows)} rows -> {out_path} "
          f"(trial elapsed so far: {total_elapsed:.1f}s)")


if __name__ == "__main__":
    main()
