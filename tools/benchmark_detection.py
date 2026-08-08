#!/usr/bin/env python3
"""Evaluate exported Aman Security verdicts without handling malware binaries.

Required CSV columns:
  expected_malicious,score

Optional columns:
  scan_ms,peak_memory_mb,expected_family,predicted_family

The tool calculates confusion-matrix metrics plus optional performance/family
metrics. It intentionally consumes exported results rather than APK samples so
the public repository never needs to bundle malicious binaries.
"""
from pathlib import Path
import argparse
import csv
import statistics


def div(a, b):
    return a / b if b else 0.0


def percentile95(values):
    if not values:
        return 0.0
    values = sorted(values)
    index = max(0, min(len(values) - 1, int(round(0.95 * (len(values) - 1)))))
    return values[index]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--threshold", type=int, default=55)
    args = ap.parse_args()
    tp = tn = fp = fn = 0
    scan_times = []
    memory = []
    family_total = family_correct = 0
    with args.csv.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            expected = str(row["expected_malicious"]).strip().lower() in {"1", "true", "yes"}
            predicted = int(row["score"]) >= args.threshold
            if expected and predicted:
                tp += 1
            elif expected:
                fn += 1
            elif predicted:
                fp += 1
            else:
                tn += 1

            if str(row.get("scan_ms") or "").strip():
                scan_times.append(float(row["scan_ms"]))
            if str(row.get("peak_memory_mb") or "").strip():
                memory.append(float(row["peak_memory_mb"]))
            expected_family = str(row.get("expected_family") or "").strip().upper()
            predicted_family = str(row.get("predicted_family") or "").strip().upper()
            if expected and expected_family and predicted_family:
                family_total += 1
                if expected_family == predicted_family:
                    family_correct += 1

    total = tp + tn + fp + fn
    print(f"BENCHMARK total={total} tp={tp} tn={tn} fp={fp} fn={fn}")
    print(
        f"detection_rate={div(tp,tp+fn):.4f} "
        f"false_positive_rate={div(fp,fp+tn):.4f} "
        f"precision={div(tp,tp+fp):.4f} accuracy={div(tp+tn,total):.4f}"
    )
    if family_total:
        print(f"family_accuracy={div(family_correct,family_total):.4f} family_samples={family_total}")
    if scan_times:
        print(
            f"scan_time_avg_ms={statistics.fmean(scan_times):.2f} "
            f"scan_time_p95_ms={percentile95(scan_times):.2f}"
        )
    if memory:
        print(
            f"peak_memory_avg_mb={statistics.fmean(memory):.2f} "
            f"peak_memory_p95_mb={percentile95(memory):.2f}"
        )


if __name__ == "__main__":
    main()
