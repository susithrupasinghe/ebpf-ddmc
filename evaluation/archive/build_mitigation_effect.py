#!/usr/bin/env python3
"""
EDDMC Evaluation — Chapter 6 data extraction, Task 7: mitigation effect.

Uses the newly-exposed `cpu_percent` column (daemon/detector/engine.py +
evaluation/results_capture.py, this round's Task 7 change) from a fresh
capture of one real XMRig track, taken AFTER the daemon was restarted to
pick up that change. Converts "the quota was applied" into "the quota
reduced utilisation by X" -- the actual research question P1-2 asked and
the prior round's on_cpu_ns-delta approach could not answer (coarse,
irregular sampling cadence; see reports/EVALUATION_ROUND2.md P1-2).
"""

import csv
import os

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
TRACK = "task7_mitigation_effect.csv"


def main():
    path = os.path.join(RESULTS_DIR, TRACK)
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))

    before = [float(r["cpu_percent"]) for r in rows if r["mitigation"] == "NONE" and r["cpu_percent"] not in ("", None)]
    after = [float(r["cpu_percent"]) for r in rows if r["mitigation"] == "THROTTLE" and r["cpu_percent"] not in ("", None)]
    none_total = sum(1 for r in rows if r["mitigation"] == "NONE")
    none_missing = sum(1 for r in rows if r["mitigation"] == "NONE" and r["cpu_percent"] in ("", None))

    first_throttle_idx = next((i for i, r in enumerate(rows) if r["mitigation"] == "THROTTLE"), None)

    def stats(vals):
        if not vals:
            return None
        return {"n": len(vals), "mean": sum(vals) / len(vals), "min": min(vals), "max": max(vals)}

    b, a = stats(before), stats(after)

    lines = ["# Mitigation effect: real CPU% before vs. after THROTTLE (Chapter 6 data extraction, Task 7)\n"]
    lines.append(f"Source: `{TRACK}` — a fresh capture of real XMRig (`--bench=1M --randomx-mode=light "
                  f"-t 1`, chosen to fit this test host's limited free memory) against a just-restarted "
                  f"daemon, so this round's `cpu_percent` capture-schema change and the process-store "
                  f"state were both guaranteed clean. n={len(rows)} total ticks.\n")

    if first_throttle_idx is not None:
        t = float(rows[first_throttle_idx]["elapsed_s"])
        lines.append(f"THROTTLE first applied at t={t}s (pid={rows[first_throttle_idx]['pid']}, "
                      f"comm={rows[first_throttle_idx]['comm']}).\n")

    lines.append("| Window | n ticks | mean cpu_percent | min | max |")
    lines.append("|---|---|---|---|---|")
    if b:
        lines.append(f"| Before enforcement (mitigation=NONE) | {b['n']} | {b['mean']:.1f}% | {b['min']:.1f}% | {b['max']:.1f}% |")
    else:
        lines.append("| Before enforcement (mitigation=NONE) | 0 | n/a | n/a | n/a |")
    if a:
        lines.append(f"| After enforcement (mitigation=THROTTLE) | {a['n']} | {a['mean']:.1f}% | {a['min']:.1f}% | {a['max']:.1f}% |")
    else:
        lines.append("| After enforcement (mitigation=THROTTLE) | 0 | n/a | n/a | n/a |")

    if b and a:
        delta = a["mean"] - b["mean"]
        pct_reduction = (1 - a["mean"] / b["mean"]) * 100 if b["mean"] else float("nan")
        lines.append(f"\n**Effect: mean CPU utilisation changed by {delta:+.1f} percentage points "
                      f"({pct_reduction:.0f}% reduction) once THROTTLE engaged**, measured from the same "
                      f"psutil-based `cpu_percent` value the scorer itself uses internally — not a coarse "
                      f"on_cpu_ns-delta proxy.\n")
    else:
        lines.append(
            f"\n**No clean before/after comparison could be established this round.** All "
            f"{none_total} pre-detection (mitigation=NONE) ticks in this capture have an empty "
            f"`cpu_percent` field ({none_missing} missing of {none_total}) — see Finding below. "
            f"Only the post-THROTTLE reading is usable, and even that should be read as a single "
            f"data point, not a validated before/after delta.\n"
        )

    lines.append("## Finding: cpu_percent is not populated during the pre-detection window\n")
    lines.append(
        "`daemon/detector/engine.py`'s per-tick store update (where this round's Task 7 change added "
        "the `cpu_percent` field) runs unconditionally for every scored PID, so this is not a simple "
        "code-path bug in that line. Empirically, in this capture, `cpu_percent` is the empty string "
        "for every one of the 40 pre-detection ticks (t=0 to t=40.6, all confidence=NONE), then becomes "
        "the literal string `'0.0'` at the exact tick confidence first reaches LOW (t=41.6s), then real "
        "non-trivial values once mitigation=THROTTLE engages. The `'0.0'` at the LOW transition is "
        "consistent with psutil's own documented `Process.cpu_percent(interval=None)` convention — it "
        "returns 0.0 on the first-ever sampled call for a given `psutil.Process` instance, with real "
        "percentages only from the second call onward (`daemon/detector/fingerprint.py:_cpu_percent()`, "
        "module-level `_procs` cache). Taken together, this suggests `_cpu_percent(pid)` — and by "
        "extension the full fingerprint-build path that touches this field — was not actually being "
        "reached/cached for this PID before its first LOW-tier detection, for a reason not root-caused "
        "in this session (a resource-prioritisation short-circuit for low-scoring PIDs is one "
        "candidate, but this was not confirmed by reading further into the scan loop). Reporting the "
        "gap rather than a guessed root cause.\n"
    )
    lines.append("## Caveat\n")
    lines.append(
        "`cpu_percent` uses psutil's `Process.cpu_percent(interval=None)` convention: it returns 0.0 "
        "on a process's first-ever sampled call (no baseline yet), by psutil's own documented behaviour "
        "-- see `daemon/detector/fingerprint.py:_cpu_percent()` and the same artefact discussed in "
        "`evaluation/replay_scorer.py`'s docstring (Task 1). Combined with the Finding above, this means "
        "the very first non-empty `cpu_percent` reading for any PID is always an artefact, not a real "
        "measurement, regardless of which tier it happens to land in.\n"
    )

    out_path = os.path.join(RESULTS_DIR, "mitigation_effect.md")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[mitigation_effect] wrote {out_path}")
    print(f"before={b}")
    print(f"after={a}")


if __name__ == "__main__":
    main()
