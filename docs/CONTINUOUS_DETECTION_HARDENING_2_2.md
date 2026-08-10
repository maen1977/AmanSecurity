# Aman Security 2.2.0 — Continuous Detection Hardening

Version 2.2 strengthens the production antivirus loop without adding malware binaries to the repository.

## Continuous installed-app protection

- New installs and updates still receive deep APK analysis.
- A periodic 24-hour WorkManager pass re-hashes user APKs and rechecks file, signer, package, and reputation indicators against the newest local threat intelligence.
- The periodic pass runs only while background protection is enabled and is constrained to battery-not-low and storage-not-low conditions.
- After an autonomous threat-intelligence refresh succeeds, Aman queues an additional lightweight installed-app rescan. This catches applications that were safe/unknown yesterday but were added to threat intelligence later.

## Alert quality

Background app alerts use a local fingerprint of risk level, app version, APK SHA-256, signer SHA-256, and confirmed threat reference. An unchanged HIGH/KNOWN_THREAT result is not repeatedly notified. A new APK, new version, changed verdict, or new confirmed threat reference can notify again.

## CI continuity

`FalsePositiveStressTest` exercises the real Kotlin verdict engine with common legitimate capabilities, while `benchmarks/false_positive_stress.csv` guards the configured 55-point decision boundary.

These gates are regression controls, not a public real-world detection-rate certification. Real detection claims still require an independently reviewed malware/benign corpus.
