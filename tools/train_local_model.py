#!/usr/bin/env python3
"""Train the tiny on-device logistic model from a labeled feature CSV.

Expected columns: label plus feature names matching detection_rules.csv MODEL rows.
The tool prints MODEL rows; it does not modify or sign the threat database.
"""
from pathlib import Path
import argparse
import csv
import math


def sigmoid(x):
    x = max(-20.0, min(20.0, x))
    return 1.0 / (1.0 + math.exp(-x))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--epochs", type=int, default=300)
    ap.add_argument("--learning-rate", type=float, default=0.05)
    ap.add_argument("--l2", type=float, default=0.001)
    args = ap.parse_args()
    with args.csv.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows or "label" not in rows[0]:
        raise SystemExit("CSV must contain a label column")
    features = [k for k in rows[0] if k != "label"]
    weights = {k: 0.0 for k in features}
    bias = 0.0
    for _ in range(args.epochs):
        gb = 0.0
        gw = {k: 0.0 for k in features}
        for row in rows:
            y = float(row["label"])
            x = {k: float(row.get(k) or 0.0) for k in features}
            z = bias + sum(weights[k] * x[k] for k in features)
            error = sigmoid(z) - y
            gb += error
            for k in features:
                gw[k] += error * x[k]
        n = float(len(rows))
        bias -= args.learning_rate * gb / n
        for k in features:
            weights[k] -= args.learning_rate * ((gw[k] / n) + args.l2 * weights[k])
    print(f"MODEL|BIAS|{bias:.6f}")
    for k in features:
        print(f"MODEL|{k}|{weights[k]:.6f}")


if __name__ == "__main__":
    main()
