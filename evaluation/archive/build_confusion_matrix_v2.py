#!/usr/bin/env python3
"""
EDDMC Evaluation — Chapter 6 data extraction, Task 6: confusion matrix v2.

The existing matrix (reports/EVALUATION_ROUND2.md P1-1) assigns ground
truth per SOURCE FILE: every row from a positive-labelled track counts as
a positive observation from t=0, including the seconds/minutes before the
detector could plausibly have accumulated enough behavioural evidence to
fire at all (the scorer's own temporal-gating design, scorer.py's own
docstring principle 2, requires sustained observation before escalating).
That folds detection LATENCY into recall, understating what the scorer
achieves once it has actually had a chance to look. This script recomputes
the same underlying CSVs four different ways so the reader can see how
much of the gap is latency vs a real miss.
"""

import csv
import os

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

CONFIDENCE_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

ALL_POSITIVE = [
    "xmrig_ground_truth_1M.csv", "evasion_throttled_1thread_3M.csv", "packed_xmrig_3M.csv",
    "network_pool_blocklist_t1.csv", "network_pool_blocklist_t2.csv", "network_pool_blocklist_t3.csv",
    "browser_wasm_miner.csv",
]
MINING_ONLY_POSITIVE = [
    "xmrig_ground_truth_1M.csv", "evasion_throttled_1thread_3M.csv", "packed_xmrig_3M.csv",
]
NEGATIVE = [
    "benign_openssl_t1.csv", "benign_openssl_t2.csv", "benign_openssl_t3.csv",
    "benign_gcc_compile_t1.csv", "benign_gcc_compile_t2.csv", "benign_gcc_compile_t3.csv",
]


def _rows(fname):
    with open(os.path.join(RESULTS_DIR, fname), newline="") as f:
        return list(csv.DictReader(f))


def _is_positive(row, threshold_rank):
    return CONFIDENCE_RANK.get(row.get("confidence", "NONE"), 0) >= threshold_rank


def _steady_state_rows(rows):
    """Drop every tick before this track's OWN first LOW+ (alert-tier)
    detection. Justification (stated once, applied uniformly): the scorer
    is explicitly temporal-gated (scorer.py docstring, "TEMPORAL GATING") —
    it cannot fire meaningfully before it has observed enough of the
    process's behaviour, by design, not by defect. Counting that startup
    window as false-negative measures detection LATENCY, which is already
    reported separately (REPORT.md §5/§7, EVALUATION_ROUND2.md P1-5) — not
    steady-state classification accuracy, which is what this reading
    isolates. No exclusion is applied to negative (benign) tracks: a true
    negative has no "pre-detection window" to exclude, and excluding one
    would only hide false positives that happened to occur early.
    """
    first_alert_idx = next(
        (i for i, r in enumerate(rows) if _is_positive(r, CONFIDENCE_RANK["LOW"])), None
    )
    if first_alert_idx is None:
        return []  # never alerted at all -- no steady-state window exists for this track
    return rows[first_alert_idx:]


def compute(positive_files, negative_files, threshold_rank, steady_state=False):
    tp = fn = tn = fp = 0
    per_file = []
    for fname in positive_files:
        rows = _rows(fname)
        if steady_state:
            excluded = len(rows)
            rows = _steady_state_rows(rows)
            excluded -= len(rows)
        else:
            excluded = 0
        pos = sum(1 for r in rows if _is_positive(r, threshold_rank))
        neg = len(rows) - pos
        tp += pos
        fn += neg
        per_file.append((fname, "positive", len(rows), pos, excluded))
    for fname in negative_files:
        rows = _rows(fname)
        neg = sum(1 for r in rows if not _is_positive(r, threshold_rank))
        pos = len(rows) - neg
        tn += neg
        fp += pos
        per_file.append((fname, "negative", len(rows), pos, 0))

    n = tp + fn + tn + fp
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) and not (
        precision != precision or recall != recall) else float("nan")
    specificity = tn / (tn + fp) if (tn + fp) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    return {
        "n": n, "tp": tp, "fn": fn, "tn": tn, "fp": fp,
        "precision": precision, "recall": recall, "f1": f1,
        "specificity": specificity, "fpr": fpr, "per_file": per_file,
    }


def fmt(x):
    return "n/a" if x != x else f"{x:.4f}"


def render_reading(title, desc, result):
    lines = [f"## {title}\n", f"{desc}\n"]
    lines.append("| Source | Label | n | positive (this reading's threshold) | excluded (pre-detection) |")
    lines.append("|---|---|---|---|---|")
    for fname, label, n, pos, excluded in result["per_file"]:
        lines.append(f"| `{fname}` | {label} | {n} | {pos} | {excluded} |")
    lines.append("")
    lines.append(f"**n = {result['n']}. TP={result['tp']} FN={result['fn']} TN={result['tn']} FP={result['fp']}**\n")
    lines.append(f"- Precision: {fmt(result['precision'])}")
    lines.append(f"- Recall: {fmt(result['recall'])}")
    lines.append(f"- F1: {fmt(result['f1'])}")
    lines.append(f"- Specificity: {fmt(result['specificity'])}")
    lines.append(f"- False-positive rate: {fmt(result['fpr'])}\n")
    return "\n".join(lines)


def main():
    out = [
        "# Confusion matrix v2 — four readings (Chapter 6 data extraction, Task 6)\n",
        "Same underlying per-observation CSVs as `reports/EVALUATION_ROUND2.md` P1-1 "
        "(one process x one scan-tick = one observation), decomposed four ways so "
        "detection latency and track scope are visible as separate factors rather than "
        "folded into a single recall figure.\n",
    ]

    r1 = compute(ALL_POSITIVE, NEGATIVE, CONFIDENCE_RANK["MEDIUM"])
    out.append(render_reading(
        "Reading 1 — as currently computed (all tracks, MEDIUM+)",
        "Every positive-labelled track from t=0, confidence >= MEDIUM. This is exactly "
        "`reports/EVALUATION_ROUND2.md` P1-1's reading, reproduced here for comparison.",
        r1,
    ))

    r2 = compute(MINING_ONLY_POSITIVE, NEGATIVE, CONFIDENCE_RANK["MEDIUM"])
    out.append(render_reading(
        "Reading 2 — mining tracks only, MEDIUM+ (excludes stratum-port and browser-WASM tracks)",
        "Removes network_pool_blocklist (0% recall root-caused as a scan-cycle-latency "
        "artefact, not a scoring miss — REPORT.md §4) and browser_wasm_miner (peaked at "
        "LOW/39, one point under this reading's own MEDIUM cutoff) from the positive set, "
        "isolating the three tracks where the scorer's core RandomX/CPU/thread signals "
        "are what's actually being measured.",
        r2,
    ))

    r3 = compute(ALL_POSITIVE, NEGATIVE, CONFIDENCE_RANK["MEDIUM"], steady_state=True)
    out.append(render_reading(
        "Reading 3 — steady state (excludes each track's own pre-detection window), MEDIUM+",
        "Exclusion rule (stated once, applied uniformly): drop every tick before a "
        "track's own first LOW+ (alert-tier) detection; a track that never alerts at all "
        "contributes no steady-state window and is reported as n=0 for that file, not "
        "silently dropped. This isolates classification accuracy from detection latency, "
        "which is already reported on its own terms elsewhere (P1-5).",
        r3,
    ))

    r4 = compute(ALL_POSITIVE, NEGATIVE, CONFIDENCE_RANK["LOW"])
    out.append(render_reading(
        "Reading 4 — any alert tier (all tracks, LOW+ rather than MEDIUM+)",
        "Same track scope as Reading 1, but the positive threshold is lowered to LOW+ "
        "(any logged alert, not just mitigation-active MEDIUM+). This is where "
        "browser_wasm_miner (peak 39/LOW) converts from a miss to a hit.",
        r4,
    ))

    out.append(
        "## Reading-to-reading takeaways\n\n"
        "- Reading 1 -> Reading 2: removing the two latency/threshold-boundary-affected "
        "tracks shows how much of Reading 1's recall gap is those two tracks specifically, "
        "versus the three core mining tracks.\n"
        "- Reading 1 -> Reading 3: shows how much of the recall gap is detection latency "
        "(pre-detection-window ticks that were never going to be positive by design) "
        "versus tracks that still don't recover even once given their own alert onward.\n"
        "- Reading 1 -> Reading 4: shows how much of the recall gap is specifically the "
        "MEDIUM-vs-LOW threshold choice (mitigation-active vs merely-logged), isolating "
        "browser_wasm_miner's boundary case from network_pool_blocklist's latency case.\n"
    )

    out_path = os.path.join(RESULTS_DIR, "confusion_matrix_v2.md")
    with open(out_path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"[confusion_matrix_v2] wrote {out_path}")


if __name__ == "__main__":
    main()
