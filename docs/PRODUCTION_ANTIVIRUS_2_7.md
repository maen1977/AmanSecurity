# Aman Security 2.7 — Production antivirus hardening

## What 2.7 adds

### 1. Multi-layer detection retained
File hash, APK identity, signer/package reputation, static rules, manifest/DEX/native-code signals, network indicators, impersonation detection, threat graph correlation, local model support, and zero-day heuristics continue to converge through evidence domains. A confirmed indicator can create a known-threat verdict; heuristic-only evidence remains bounded to reduce false positives.

### 2. Threat-intelligence anti-poisoning and health
`AutonomousFeedPolicy` assigns each source a trust tier, lookup TTL, minimum/maximum entry count, and whether that source may independently confirm a threat. Remote snapshots are bounded before storage. Community phishing data remains review-only. Failed sources never overwrite their last-known-good index. Per-source last success and consecutive failure counts are stored locally and shown as source health.

Immutable malicious file SHA-256 indicators remain useful after source outages because the file content identified by the hash does not change. Transient phishing and command-and-control infrastructure expires according to source-specific TTLs.

### 3. Event-driven and recurring protection
When background protection is enabled, Aman deep-scans newly installed **or updated** user apps. It also runs conservative recurring installed-app reputation rescans and checks new/changed files only inside a folder explicitly selected by the user. Remediation remains user initiated.

### 4. Web protection
Web Guard continues to scan links locally before handing them to an external browser. Confirmed active malicious/phishing indicators are blocked, community-only indicators request review, and heuristic risk combinations produce caution. Aman does not claim HTTPS decryption or a hidden VPN.

### 5. Protection-readiness and app integrity
A local readiness score summarizes enabled layers: bundled database health, autonomous source freshness, background protection, Web Guard status, Android patch comparison, and application signing state. The score is a configuration/readiness signal — not a probability that the device is malware-free.

For production distributions, `AMAN_RELEASE_CERT_SHA256` can contain the public SHA-256 fingerprint of the expected app-signing certificate. The runtime compares its own signer to that fingerprint. Private signing keys are never bundled.

### 6. Real-corpus validation pipeline
`tools/benchmark_detection.py` now supports minimum sample counts, minimum malicious/benign counts, reviewed-row enforcement, stable sample SHA-256 identifiers, source-group tracking, detection-rate limits, false-positive-rate limits, precision, family accuracy, time, and memory metrics.

The repository intentionally contains no malware binaries. `benchmarks/reviewed_detection_results.csv` is empty until results are exported from an isolated, independently reviewed corpus. Internal regression fixtures are useful for regressions but are not a real-world antivirus certification.

### 7. Release evidence
The automatic build workflow runs on pushes to `main`, keeps manual dispatch, and has no schedule or threat-update job. It runs quality gates, unit tests, release lint, builds APK/AAB outputs, captures a release dependency inventory, writes SHA-256 checksums for artifacts, and uploads verification reports.

## Android boundaries kept explicit
A normal Android app cannot inspect arbitrary private memory/files of other sandboxed apps. Aman therefore builds protection from package inspection, permitted file access, static APK analysis, event-driven install/update scanning, local URL protection, threat intelligence, and conservative remediation rather than claiming Windows-style unrestricted endpoint access.

## Before public release
A fully green automatic workflow is required. For a real production-quality detection claim, populate the reviewed corpus results from an isolated lab and enforce release-specific thresholds. Configure normal Android release signing and, if desired, the expected public signing-certificate fingerprint. Test on representative Android versions and devices before distribution.
