#!/usr/bin/env python3
"""
EDDMC Evaluation — P1-1: confusion matrix (precision/recall/F1/FPR).

Unit of classification (per work order P1-1's recommendation, stated
explicitly here so it can be defended in the thesis): ONE OBSERVATION =
one tracked process at one scan-poll tick (one row in a results_capture.py
CSV). A process is counted DETECTOR-POSITIVE at that tick if its reported
confidence is MEDIUM or above (score >= throttle_threshold = 40) -- i.e.
the tier at which real mitigation (cgroup throttle) first applies, not
merely an ALERT-level log entry. This threshold choice matters and is
stated explicitly: using LOW (>=20) instead would inflate recall on
several ground-truth-positive CSVs whose scores plateau at LOW for many
ticks before ever reaching MEDIUM (see browser_wasm_miner.csv), at the
cost of counting mitigation-inactive detections as full positives.

Ground truth is assigned per SOURCE FILE, not per row: every row in a file
under POSITIVE_SOURCES is a real miner-shaped process (should ideally be
flagged MEDIUM+ at least once it's been running long enough -- see the
temporal/sustained-detection design in scorer.py, which deliberately
delays escalation); every row under NEGATIVE_SOURCES is a real benign
workload (should never be flagged MEDIUM+).

All data reported here is POST-FIX (after the DetectionEngine thread-death
bug and the scratchpad false-positive heuristic were both fixed) -- there
is no separate PRE-FIX dataset to report alongside it, since the pre-fix
runs simply produced non-functional 0/NONE output, not a meaningfully
comparable classification result (see reports/EVALUATION_ROUND2.md P0-2
for that bug's full writeup). This is stated explicitly per the work
order's "report pre/post-fix separately, do not pool" instruction -- there
is nothing to pool here because the "before" condition wasn't a working
classifier at all.

Usage: python3 compute_confusion_matrix.py
"""
import csv
import glob
import os

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

POSITIVE_SOURCES = [
    "xmrig_ground_truth_*.csv",
    "evasion_throttled_*.csv",
    "packed_xmrig_*.csv",
    "network_pool_blocklist_t*.csv",
    "browser_wasm_miner.csv",
]
NEGATIVE_SOURCES = [
    "benign_openssl_t*.csv",
    "benign_gcc_compile_t*.csv",
]

CONFIDENCE_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
POSITIVE_THRESHOLD_RANK = CONFIDENCE_RANK["MEDIUM"]  # score >= 40, mitigation-active tier


def _rows_from(patterns):
    out = []
    for pat in patterns:
        for path in sorted(glob.glob(os.path.join(RESULTS_DIR, pat))):
            with open(path, newline="") as f:
                rows = list(csv.DictReader(f))
            out.append((os.path.basename(path), rows))
    return out


def _is_detector_positive(row):
    return CONFIDENCE_RANK.get(row.get("confidence", "NONE"), 0) >= POSITIVE_THRESHOLD_RANK


def main():
    positive_files = _rows_from(POSITIVE_SOURCES)
    negative_files = _rows_from(NEGATIVE_SOURCES)

    tp = fn = tn = fp = 0
    per_file = []

    for fname, rows in positive_files:
        pos = sum(1 for r in rows if _is_detector_positive(r))
        neg = len(rows) - pos
        tp += pos
        fn += neg
        per_file.append((fname, "positive", len(rows), pos, neg))

    for fname, rows in negative_files:
        neg = sum(1 for r in rows if not _is_detector_positive(r))
        pos = len(rows) - neg
        tn += neg
        fp += pos
        per_file.append((fname, "negative", len(rows), pos, neg))

    n = tp + fn + tn + fp
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    specificity = tn / (tn + fp) if (tn + fp) else float("nan")

    print(f"Unit of classification: one (process, scan-tick) observation; "
          f"detector-positive iff confidence >= MEDIUM (score >= 40, throttle_threshold)")
    print(f"n = {n} total observations ({tp+fn} from positive-labelled sources, "
          f"{tn+fp} from negative-labelled sources)")
    print()
    print("Per-file breakdown:")
    for fname, label, total, pos_count, neg_count in per_file:
        if label == "positive":
            print(f"  [{label:>8}] {fname:<40} n={total:>5}  detector-positive={pos_count:>5} ({100*pos_count/total:.1f}%)")
        else:
            print(f"  [{label:>8}] {fname:<40} n={total:>5}  detector-negative={neg_count:>5} ({100*neg_count/total:.1f}%)")
    print()
    print(f"Confusion matrix: TP={tp} FN={fn} TN={tn} FP={fp}")
    print(f"Precision = {precision:.4f}")
    print(f"Recall    = {recall:.4f}")
    print(f"F1        = {f1:.4f}")
    print(f"Specificity (TNR) = {specificity:.4f}")
    print(f"False-positive rate = {fpr:.4f}")


if __name__ == "__main__":
    main()
