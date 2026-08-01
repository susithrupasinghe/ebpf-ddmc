#!/usr/bin/env python3
"""
EDDMC postfix verification, Step 4 — per-feature contribution breakdown at
the peak tick of evaluation/results/postfix/xmrig_postfix.csv, in the same
leave-one-out form as evaluation/results/ablation_leave_one_out.md, plus a
direct pre/post comparison against the pre-fix xmrig_ground_truth_1M.csv
peak tick. Writes evaluation/results/postfix/feature_comparison.md.
Read-only: does not touch any existing evaluation result.
"""

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from replay_scorer import replay_row, ABLATION_GROUPS

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
POSTFIX_DIR = os.path.join(RESULTS_DIR, "postfix")


def load_peak(path, comm_filter=None):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if comm_filter:
        rows = [r for r in rows if r["comm"] == comm_filter]
    return max(rows, key=lambda r: float(r["score"]))


def contributions_at(row):
    baseline, cpu_used, cpu_exact = replay_row(row)
    out = {}
    for name, keys in ABLATION_GROUPS.items():
        overrides = {k: 0 for k in keys}
        ablated, _, _ = replay_row(row, weight_overrides=overrides)
        out[name] = baseline.score - ablated.score
    return baseline, out, cpu_used, cpu_exact


def main():
    pre = load_peak(os.path.join(RESULTS_DIR, "xmrig_ground_truth_1M.csv"), "xmrig")
    post = load_peak(os.path.join(POSTFIX_DIR, "xmrig_postfix.csv"), "xmrig")

    pre_result, pre_contrib, pre_cpu, pre_cpu_exact = contributions_at(pre)
    post_result, post_contrib, post_cpu, post_cpu_exact = contributions_at(post)

    lines = ["# Postfix per-feature contribution comparison\n"]
    lines.append(f"Pre-fix peak: `xmrig_ground_truth_1M.csv` t={pre['elapsed_s']}s, "
                  f"score={pre_result.score}/{pre_result.confidence}\n")
    lines.append(f"Post-fix peak: `xmrig_postfix.csv` t={post['elapsed_s']}s, "
                  f"score={post_result.score}/{post_result.confidence}\n")

    lines.append("| Feature (weighted group) | Pre-fix contribution | Post-fix contribution | Newly nonzero? |")
    lines.append("|---|---|---|---|")
    for name in ABLATION_GROUPS:
        pre_v = pre_contrib.get(name, 0.0)
        post_v = post_contrib.get(name, 0.0)
        newly = "**YES**" if pre_v == 0 and post_v != 0 else ("no" if pre_v == post_v else "changed")
        lines.append(f"| {name} | {pre_v:.1f} | {post_v:.1f} | {newly} |")

    lines.append(f"\ncpu_percent used in replay: pre-fix {pre_cpu} (recovered exactly: {pre_cpu_exact}), "
                 f"post-fix {post_cpu} (recovered exactly: {post_cpu_exact}) — unrelated to this fix, "
                 f"still subject to the separate scan-cadence limitation documented in Task 7.\n")

    lines.append("## Full reason text\n")
    lines.append(f"**Pre-fix**: {'; '.join(pre_result.reasons)}\n")
    lines.append(f"**Post-fix**: {'; '.join(post_result.reasons)}\n")

    out_path = os.path.join(POSTFIX_DIR, "feature_comparison.md")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[postfix] wrote {out_path}")
    print(f"pre score={pre_result.score} post score={post_result.score}")


if __name__ == "__main__":
    main()
