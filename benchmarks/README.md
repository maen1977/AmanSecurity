# Detection quality corpora

`regression_detection.csv` is a safe synthetic regression fixture. It checks that CI thresholds and reporting do not regress, but it is **not** evidence of real-world detection performance.

`reviewed_detection_results.csv` is intentionally empty in the public project. Populate it only with **exported verdict results** from an isolated, reviewed lab corpus. Do not commit malware APKs, DEX files, or infected archives. Each row is a verdict summary, not a sample.

When reviewed rows are present, GitHub Actions enforces:
- detection rate >= 95%
- false-positive rate <= 1%
- precision >= 95%
- family accuracy >= 80% when family labels are available

These thresholds are release gates, not marketing claims. A public detection-rate claim should use an independent, representative corpus and document methodology.
