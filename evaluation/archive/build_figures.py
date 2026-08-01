#!/usr/bin/env python3
"""
EDDMC Evaluation — Chapter 6 data extraction, Task 3: figures.

Three PNGs into evaluation/figures/, 150dpi+, axis labels + legends, no
chart titles (captions belong in the dissertation). Every value plotted
traces to an existing CSV or, for fig_latency_distribution, to the 13
scan-cycle-gap measurements already published in
evaluation/results/REPORT.md §4 (there is no larger raw dataset than that;
this is stated on the figure itself, not hidden).

Colours are the dataviz skill's validated categorical palette
(references/palette.md), assigned in fixed order -- never re-cycled per
track.
"""

import csv
import os
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
FIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figures")

BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
GRID_GRAY = "#9a9a9a"


def _read(fname):
    with open(os.path.join(RESULTS_DIR, fname), newline="") as f:
        return list(csv.DictReader(f))


def _max_score_by_tick(rows):
    """Aggregate multiple PIDs sharing one capture tick (parallel worker
    processes in the benign tracks) down to the worst-case score per tick,
    so 'one line per track' is well-defined even for multi-PID tracks."""
    by_tick = {}
    for r in rows:
        t = float(r["elapsed_s"])
        by_tick[t] = max(by_tick.get(t, 0.0), float(r["score"]))
    return sorted(by_tick.items())


def fig_score_trajectory():
    tracks = [
        ("XMRig ground truth (--bench)", "xmrig_ground_truth_1M.csv", BLUE),
        ("XMRig, UPX-packed", "packed_xmrig_3M.csv", ORANGE),
        ("Benign: OpenSSL crypto benchmark", "benign_openssl_t1.csv", AQUA),
        ("Benign: parallel gcc compilation", "benign_gcc_compile_t1.csv", YELLOW),
    ]

    fig, ax = plt.subplots(figsize=(9, 5.5))

    for label, fname, color in tracks:
        series = _max_score_by_tick(_read(fname))
        xs = [t for t, _ in series]
        ys = [s for _, s in series]
        ax.plot(xs, ys, color=color, linewidth=2, label=label, solid_capstyle="round")

    for y, tier in [(20, "LOW"), (40, "MEDIUM"), (60, "HIGH"), (80, "CRITICAL")]:
        ax.axhline(y, color=GRID_GRAY, linewidth=1, linestyle=(0, (4, 3)), zorder=0)
        ax.text(ax.get_xlim()[1] if False else 1, y + 1.2, tier, color=GRID_GRAY, fontsize=8, va="bottom")

    ax.set_xlabel("Elapsed time (s)")
    ax.set_ylabel("Composite suspicion score (0-100)")
    ax.set_ylim(-3, 103)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper left", frameon=False, fontsize=9)
    fig.tight_layout()
    out = os.path.join(FIG_DIR, "fig_score_trajectory.png")
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"[figures] wrote {out}")


def fig_feature_contribution():
    with open(os.path.join(RESULTS_DIR, "feature_contributions.csv"), newline="") as f:
        rows = list(csv.DictReader(f))

    mining_rows = [r for r in rows if r["track"] == "mining"]
    benign_rows = [r for r in rows if r["track"] == "benign"]

    mining_peak = max(mining_rows, key=lambda r: float(r["running_score"]))
    benign_peak = max(benign_rows, key=lambda r: float(r["running_score"]))

    def contributions_at(rows, ts, pid):
        # Several tracks have multiple PIDs sharing one capture tick
        # (parallel worker processes) -- must key on (timestamp, pid)
        # together, or one PID's rows silently overwrite another's.
        out = {}
        for r in rows:
            if (r["timestamp"], r["pid"]) == (ts, pid) and not r["feature_name"].startswith("[FLOOR") and not r["feature_name"].startswith("[CAP"):
                out[r["feature_name"]] = float(r["contribution"] or 0)
        return out

    m = contributions_at(mining_rows, mining_peak["timestamp"], mining_peak["pid"])
    b = contributions_at(benign_rows, benign_peak["timestamp"], benign_peak["pid"])
    features = list(m.keys())  # both tracks emit the same 9 feature names, same order

    x = range(len(features))
    width = 0.38
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.bar([i - width / 2 for i in x], [m[f] for f in features], width, color=BLUE, label="XMRig ground truth (--bench), peak tick")
    ax.bar([i + width / 2 for i in x], [b[f] for f in features], width, color=AQUA, label="Benign: OpenSSL, peak tick")

    ax.set_xticks(list(x))
    ax.set_xticklabels(features, rotation=35, ha="right", fontsize=8)
    ax.set_ylabel("Weighted contribution to composite score")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper right", frameon=False, fontsize=9)
    ax.text(0.01, 0.98, "Excludes hard-evidence floors (applied after the weighted sum) — see ablation_leave_one_out.md",
            transform=ax.transAxes, fontsize=7, color=GRID_GRAY, va="top")
    fig.tight_layout()
    out = os.path.join(FIG_DIR, "fig_feature_contribution.png")
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"[figures] wrote {out}")


def fig_latency_distribution():
    # The only scan-cycle-gap dataset that exists: the 13 gaps measured and
    # published in evaluation/results/REPORT.md §4 by direct daemon-log
    # timestamp inspection. No larger raw sample was captured this round —
    # stated on the figure itself rather than implied to be a bigger n.
    gaps = [13.2, 14.9, 25.4, 13.7, 14.4, 18.7, 21.9, 22.0, 17.1, 22.4, 22.8, 34.1, 22.0]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(gaps, bins=8, color=BLUE, edgecolor="white", linewidth=1.2)
    ax.axvline(5, color=ORANGE, linewidth=2, linestyle=(0, (4, 3)), label="Configured scan interval (5s)")
    ax.set_xlabel("Scan-cycle gap (s)")
    ax.set_ylabel("Count")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper right", frameon=False, fontsize=9)
    ax.text(0.98, 0.80, "n=13 gaps, single measurement run\n(REPORT.md §4)", transform=ax.transAxes,
            fontsize=8, color=GRID_GRAY, ha="right", va="top")
    fig.tight_layout()
    out = os.path.join(FIG_DIR, "fig_latency_distribution.png")
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"[figures] wrote {out}")


if __name__ == "__main__":
    fig_score_trajectory()
    fig_feature_contribution()
    fig_latency_distribution()
