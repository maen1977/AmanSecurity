#!/usr/bin/env python3
"""Generate pre-trained weights for the on-device LocalReasoningClassifier.

Trains a tiny logistic regression on synthetic app profiles:
malicious profiles carry high values on surveillance/telemetry/exfiltration
dimensions; benign profiles carry mild values on camera/audio/ads only.
Outputs a small CSV that ships inside the cloud threat database and is
loaded by ThreatDbValidator.
"""
import csv
import json
import math
import random
import hashlib
import os

random.seed(42)

DIMENSIONS = [
    "surveillance", "stealth", "exfiltration", "persistence", "monetization",
    "privilege", "anti_analysis", "impersonation",
]

def sigmoid(x):
    return 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, x))))

def synth():
    rows = []
    for _ in range(400):
        bad = random.random() < 0.35
        if bad:
            v = {d: random.uniform(0.4, 1.0) for d in random.sample(DIMENSIONS, k=random.randint(3, 6))}
        else:
            mild = random.sample(DIMENSIONS, k=random.randint(1, 2))
            v = {d: random.uniform(0.0, 0.3) for d in mild}
        rows.append((v, 1 if bad else 0))
    return rows

def train(rows, epochs=1200, lr=0.25):
    w = {d: 0.0 for d in DIMENSIONS}
    bias = -0.5
    for _ in range(epochs):
        for v, y in rows:
            z = bias + sum(w[d] * v.get(d, 0.0) for d in DIMENSIONS)
            p = sigmoid(z)
            err = y - p
            bias += lr * err
            for d in DIMENSIONS:
                w[d] += lr * err * v.get(d, 0.0)
    return w, bias

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rows = synth()
    w, bias = train(rows)

    # Sanity check
    tp = fp = fn = tn = 0
    for v, y in rows:
        z = bias + sum(w[d] * v.get(d, 0.0) for d in DIMENSIONS)
        pred = 1 if sigmoid(z) >= 0.5 else 0
        if pred == 1 and y == 1: tp += 1
        elif pred == 1 and y == 0: fp += 1
        elif pred == 0 and y == 1: fn += 1
        else: tn += 1
    n = tp + fp + fn + tn
    acc = (tp + tn) / n
    fpr = fp / (fp + tn) if (fp + tn) else 0
    print(f"REASONING_MODEL train_ok samples={n} accuracy={acc:.4f} false_positive_rate={fpr:.4f}")

    out_path = os.path.join(root, "threat-db", "reasoning_model_weights.csv")
    with open(out_path, "w", newline="") as fh:
        fh.write("# reasoning_model_weights v1 — on-device LocalReasoningClassifier\n")
        fh.write("dimension,weight\n")
        for d in DIMENSIONS:
            fh.write(f"{d},{round(w[d], 6)}\n")
        fh.write(f"bias,{round(bias, 6)}\n")

    dbzip_dir = os.path.join(root, "dist", "cloud-threat-db")
    os.makedirs(dbzip_dir, exist_ok=True)

if __name__ == "__main__":
    main()
