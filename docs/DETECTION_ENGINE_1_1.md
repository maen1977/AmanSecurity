> Historical 1.1 design note. Superseded by `REAL_ANTIVIRUS_CORE_2_0.md`.

# Aman Security 1.1.0 detection-engine design

## Goal

Version 1.1.0 implements the requested 20-part detection upgrade as a **layered local anti-malware architecture**. It intentionally avoids a claim of perfect detection. Unknown malware, heavily virtualized/packed code, server-side behavior, runtime-loaded payloads, and Android sandbox restrictions can all reduce what static/on-device analysis can see.

## Evidence hierarchy

1. **Confirmed signed indicators** — file SHA-256, signer/package identity, signed reputation, or a confirmed local URL/host match. These can produce `KNOWN_THREAT`.
2. **High-confidence rules and behavior chains** — combinations of manifest and DEX evidence. These can produce high/very-high risk when independent engines agree.
3. **Reputation/packer/impersonation/local-model hints** — supporting evidence only unless corroborated. Low-confidence evidence is capped to prevent a single weak signal from becoming a high verdict.
4. **User exact-hash allowlist** — caps heuristic escalation but does not erase findings or rewrite a known result as clean.

## Engine modules

- `SignatureRuleEngine` — signed all/any marker rules.
- `StaticBehaviorEngine` — spyware/stalkerware/banker/RAT/dropper/ransomware chains.
- `NetworkIndicatorExtractor` — bounded URL/domain extraction.
- `ImpersonationDetector` — protected-brand package-name comparison.
- `LocalMalwareModel` — lightweight signed-weight logistic inference.
- `VerdictEngine` — combines independent findings and controls false positives.
- Existing `SignatureDatabase`, `UrlScanner`, `ApkStaticAnalyzer`, and `InstalledAppScanner` provide confirmed hash/identity matching and APK/package integration.

## APK safety bounds

The analyzer never executes the APK. It limits APK size, ZIP entry count, declared uncompressed size, DEX bytes inspected, and network indicators looked up. Temporary selected-APK copies are deleted after analysis. Installed APKs are re-hashed before deep analysis so a changed source does not reuse a stale verdict.

## Threat database schema 4

The signed manifest now covers:

- `signatures.csv` — file hashes.
- `url_indicators.csv` — normalized URL/host hashes.
- `apk_indicators.csv` — package/signer identity hashes.
- `detection_rules.csv` — rules, protected brands, local-model weights, reputation records, and source/family/confidence/first/last-seen metadata.

The updater refuses a schema older than 4 for this release, verifies the manifest signature, verifies every database hash, prevents serial rollback, disables redirects, and only accepts HTTPS update endpoints.

## Threat-intelligence pipeline

`tools/update_threat_intel.py` is indicator-only. It can import recent MalwareBazaar hash metadata and URLhaus URLs using an abuse.ch Auth-Key, plus a local reviewed phishing URL file and reviewed hash-reputation CSV rows for file/signer/package/host identities. For URL data it stores hashes of normalized URLs/hosts instead of live malicious URLs. It never downloads malware binaries.

Operational process:

1. Import indicators into a maintainer working copy.
2. Review diffs, source confidence, duplicates, family names, and likely false-positive impact.
3. Increase manifest serial/version as appropriate.
4. Sign the manifest offline.
5. Run threat DB, detection, localization, quality, release, unit, and lint gates.
6. Publish the signed DB only after review.

## Local machine-learning layer

`tools/train_local_model.py` trains a small logistic model from a labeled feature CSV and prints `MODEL` rows for review. The app executes the model locally. The bundled model weights are conservative bootstrap weights; they are **not evidence of a production-scale training corpus**. Before treating this layer as a strong detector, train/validate on a legally obtained, representative labeled dataset with strict train/test separation and measure false positives on large clean-app sets.

## Benchmarking

`tools/benchmark_detection.py` calculates detection rate, false-positive rate, and precision from exported expected labels and verdict scores. This avoids bundling malware samples in the repository. Release decisions should track both detection and false-positive performance; optimizing only detection rate would make the product noisy and unsafe.

## Optional cloud reputation

Historical 1.1 note: this endpoint design was replaced in 2.0 by signed two-character SHA-256 prefix shards hosted on GitHub. See `REAL_ANTIVIRUS_CORE_2_0.md` and `CLOUD_REPUTATION.md`.

## Background protection

- Package install/update events schedule a deep scan of the affected package.
- Broad installed-app inventory scans use a faster path to control CPU and battery.
- Protected-folder scanning stays SAF-scoped and periodic.
- Historical 1.1 behavior used 12-hour checks; 2.0 uses six-hour signed update checks.
- No background path automatically deletes, uninstalls, or quarantines content.

## Remaining real-world work before strong marketing claims

Architecture and test gates are now present, but high-quality malware detection requires ongoing operations: continuously refreshed signed feeds, reviewed family labels, a large clean-app corpus, legally sourced malicious indicators/samples in an isolated research environment, regression benchmarking, telemetry only where explicitly consented, and periodic tuning against false positives. These operational datasets are deliberately not bundled in this public project.
