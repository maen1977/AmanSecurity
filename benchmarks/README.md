# Detection validation

`regression_detection.csv`, `synthetic_detection.csv`, and `false_positive_stress.csv` are deterministic internal regression fixtures. They are useful for preventing detection regressions, but **they are not real-world antivirus detection-rate claims**.

`reviewed_detection_results.csv` is intentionally shipped empty. Populate it only with exported verdict results from an independently reviewed benign/malicious corpus tested in an isolated lab. Do not commit malware APKs, DEX files, executables, private keys, or licensed sample content to this repository.

For every reviewed row, record a stable `sample_sha256`, set `review_status=reviewed`, and use `source_group` to identify the corpus/provider without storing the sample itself. A production evaluation can then be run with minimum corpus-size and quality thresholds, for example:

```bash
python3 tools/benchmark_detection.py benchmarks/reviewed_detection_results.csv \
  --require-reviewed \
  --min-samples 1000 --min-malicious 500 --min-benign 500 \
  --min-detection-rate 0.95 --max-false-positive-rate 0.01 \
  --json-out build/production-validation.json
```

Those thresholds are a validation target, not a statement that the bundled project currently achieves them. Keep the exported CSV and JSON report as release evidence.
