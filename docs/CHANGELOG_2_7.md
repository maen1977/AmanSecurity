# Aman Security 2.7.0 — Production Antivirus Hardening

- Added declarative trust/TTL/count policy for every autonomous threat source.
- Added per-source freshness, last-attempt, stale-source, and consecutive-failure health tracking.
- Preserved immutable file-hash detections across temporary feed outages while keeping transient phishing/C2 TTL expiry.
- Added protection-readiness evaluation and localized status in the main UI.
- Added optional public release-certificate SHA-256 pinning and runtime signer inspection.
- Added app-update event scanning (`PACKAGE_REPLACED`) in addition to new-install scanning.
- Added reviewed-corpus production validation schema/metrics without bundling malware binaries.
- Added minimum corpus-size and reviewed-label enforcement options to benchmark tooling.
- Added threat-intel policy, Android string-format, production-validation, and release-hardening gates.
- Added automatic dependency inventory, build artifact SHA-256 checksums, and verification-report artifacts to the single build workflow.
- Kept threat updates on-device: no scheduled GitHub threat-update job, no API keys, and no threat-update private keys.
- Version raised to 2.7.0 / code 17.

## Smart security interface refresh
- Added a prominent dynamic Security Score dashboard with protected/attention/action-required states.
- Added Smart Scan progress state and compact result card for installed-app and file scans.
- Added six functional quick-protection actions for apps, files, web protection, background protection, quarantine, and threat-intelligence refresh.
- Connected dashboard severity to protection posture plus the most recent installed-app/file findings.
- Modernized existing protection cards with larger rounded surfaces while retaining all detailed controls and reports.
- Added `smart_ui_gate.py` so the dashboard, scan state, results state, quick actions, and automatic main-branch build trigger cannot silently disappear.
