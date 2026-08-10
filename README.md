# Aman Security 2.7.0

Android antivirus / anti-malware project with strict Arabic and English UI separation, on-device APK/app analysis, phishing protection, Web Guard, encrypted quarantine, install/update event scanning, recurring installed-app rescans, behavior/zero-day heuristics, autonomous threat-intelligence updates, source-health tracking, production-corpus validation tooling, and configurable release self-integrity checking.

## 2.7 production antivirus hardening

Aman 2.7 keeps the 2.6 autonomous no-key threat-intelligence architecture and adds source-specific trust/TTL/size policies, last-known-good retention, per-source failure/freshness health, a protection-readiness dashboard signal, install **and update** package events, a configurable release signing-certificate fingerprint check, reviewed-corpus validation infrastructure, dependency/report artifacts, and SHA-256 checksums for CI build outputs.

The app itself refreshes public threat intelligence about every six hours when Android permits background work and the network is connected. GitHub Actions are **not** used for threat-intelligence updates. The single build workflow runs automatically on pushes to `main` and can also be started manually. No API keys or threat-update private keys are required.

The updater downloads only bounded text/JSON/HTML indicator data from fixed HTTPS sources, rejects executable/archive payloads, validates each source independently, keeps last-known-good data when a source fails, expires transient phishing/C2 data by TTL, and re-evaluates installed apps after successful intelligence refreshes when background protection is enabled. Community-only phishing intelligence produces review/caution rather than a confirmed-malicious verdict by itself.

See `docs/PRODUCTION_ANTIVIRUS_2_7.md` and `docs/AUTONOMOUS_THREAT_INTELLIGENCE_2_6.md`.

## Development and release checks

```bash
python3 tools/quality_gate.py
```

The automatic GitHub workflow then runs Android unit tests, release lint, builds an installable debug APK and an unsigned release AAB, records the release dependency inventory, generates SHA-256 checksums, and uploads verification reports.

For production corpus validation, keep malware/benign samples outside the repository and export only reviewed verdict metadata to `benchmarks/reviewed_detection_results.csv`. The shipped reviewed file is intentionally empty; internal regression fixtures are not real-world detection-rate claims. See `benchmarks/README.md`.

For release self-integrity, a distributor can provide the **public** SHA-256 fingerprint of the expected Android app-signing certificate as the Gradle property `AMAN_RELEASE_CERT_SHA256`. No private signing key is bundled or required by the source tree.

## Upgrading an older GitHub repository

Do not only overlay the ZIP on top of old repository files: Git does not remove legacy files that are absent from a new ZIP. Aman 2.7 has no GitHub threat-update workflow. It keeps one build-only workflow at `.github/workflows/build.yml`.

Use the cleanup helper before committing an overlay onto an old clone:

```bash
python3 tools/repository_cleanup_2_6.py        # preview
python3 tools/repository_cleanup_2_6.py --apply
```

If GitHub still reports `minimumSignedReputationEntries`, the old pre-2.6 pipeline is still present in the repository. Remove the stale workflow/gates rather than restoring the retired signed-reputation configuration.
