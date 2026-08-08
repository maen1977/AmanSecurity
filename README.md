# Aman Security 1.1.0 — Detection Engine Upgrade

Aman Security is a bilingual Android mobile-security scanner with strict Arabic/English UI separation. Version `1.1.0` upgrades the project from a signature/risk scanner into a layered anti-malware architecture while keeping Android privacy and sandbox limits explicit.

## What 1.1.0 adds

1. **Refreshable threat intelligence** — signed file, URL/host/IP, APK identity, reputation, source/family/confidence/first-seen metadata, protected-brand, rule, and local-model records.
2. **YARA-style local signature rules** — rules combine required and optional static markers without executing the APK.
3. **Deeper bounded DEX inspection** — dynamic loading, command execution, SMS APIs, device identifiers, screen capture, clipboard, installer/downloader, reflection, networking, encryption, and native loading markers.
4. **Behavior-combination analysis** — stronger conclusions require meaningful combinations such as Accessibility + overlay or SMS + contacts + boot persistence.
5. **Packing/obfuscation indicators** — known packer entry names, secondary DEX payloads, reflection-heavy dynamic-code patterns.
6. **Network IOC extraction** — bounded extraction of URLs/domains from scanned DEX bytes and local matching against the signed URL database.
7. **Reputation engine** — file, signer, package, and host reputation records can be carried by the signed rules database.
8. **Impersonation detection** — protected-brand package profiles identify look-alikes as low-confidence context, not an automatic malware verdict.
9. **Spyware/stalkerware specialization** — dedicated families and behavior chains for spyware, stalkerware, banker, RAT, dropper, ransomware, phishing, adware, and riskware.
10. **Static behavioral detection** — code/manifest evidence is combined into behavior findings without running untrusted APK code.
11. **Optional cloud hash reputation** — disabled by default; only available when an HTTPS reputation endpoint is configured and the user opts in. The client sends the SHA-256 identifier for a user-selected APK scan only, never the APK file; background installed-app scans stay local.
12. **Local ML inference** — lightweight logistic inference uses signed model weights. A training utility is included, but production weights must be trained and benchmarked on a reviewed labeled dataset before making strong detection claims.
13. **Multi-engine verdict system** — independent engines contribute weighted evidence; confirmed malicious indicators override heuristics.
14. **False-positive controls** — one low-confidence heuristic cannot produce a high verdict; exact allowlisting caps heuristic escalation while preserving the underlying findings.
15. **Threat-family classification** — malware, trojan, spyware, stalkerware, banker, RAT, dropper, ransomware, phishing, riskware, adware, and safe test signatures.
16. **Scheduled signed database updates** — WorkManager checks for signed threat updates every 12 hours when network is available and battery is not low.
17. **Separated scanner engines** — signature, behavior, network, impersonation, local-model, reputation, and verdict logic are separate modules.
18. **Regression/benchmark tooling** — unit tests cover the new pure detection engines; `tools/benchmark_detection.py` calculates detection rate, false-positive rate, and precision from labeled exported scores.
19. **Post-install deep protection** — newly installed/updated user apps receive the deeper static analysis path; broad inventory scans retain the faster layer to control battery/CPU use.
20. **Release upgrade** — version `1.1.0` (`versionCode 9`), API 36, R8/resource shrinking, release AAB support, and one automatic GitHub Actions workflow.

## Existing protection retained

- File/APK SHA-256 scan and signed threat database.
- Installed-app permission/source/signing-certificate review.
- Encrypted AES-GCM quarantine backed by Android Keystore; no automatic deletion/quarantine.
- Exact-hash exclusions and bounded local scan history.
- Local URL/phishing scanner and Android share-to-scan flow.
- SAF protected-folder scanning without broad storage permission.
- Event-driven scan after package installation/update.
- Cleartext networking disabled in release.
- Strict English/Arabic localization gate.

## Detection-safety model

Aman Security does **not** claim that any antivirus can identify every harmful program or every zero-day. Detection quality depends on the breadth, freshness, and review quality of threat intelligence plus real-world false-positive testing. The project therefore separates confirmed indicators from heuristic/ML findings and exposes confidence instead of treating a single permission or obfuscation marker as proof of malware.

No malware binary is bundled or downloaded by the threat-intelligence tooling. `tools/update_threat_intel.py` imports indicators only. After reviewing database changes, the maintainer must increment/sign the manifest using the offline update-signing key; the private key must never be committed or packaged with the app.

## Threat intelligence maintenance

Example indicator-only imports:

```bash
export ABUSECH_AUTH_KEY='...'
python3 tools/update_threat_intel.py --malwarebazaar --urlhaus --limit 1000
python3 tools/update_threat_intel.py --phishing-file reviewed_phishing_urls.txt --limit 5000
python3 tools/update_threat_intel.py --reputation-file reviewed_reputation.csv --limit 5000
```

Then review the diff, update/sign the manifest with the offline key, and run the full gates before publishing the database. See `threat-db/SOURCES.md` and `docs/DETECTION_ENGINE_1_1.md`.

## Local model training and benchmarking

```bash
python3 tools/train_local_model.py labeled_features.csv > model_rows.txt
python3 tools/benchmark_detection.py labeled_scores.csv --threshold 55
```

The included on-device model is a small inference layer, not a substitute for confirmed signatures, reputation, or behavior analysis.

## Build checks

```bash
python3 tools/verify_localization.py
python3 tools/verify_threat_db.py
python3 tools/detection_gate.py
python3 tools/quality_gate.py
python3 tools/release_gate.py
python3 tools/verify_single_workflow.py
gradle :app:testDebugUnitTest :app:lintRelease :app:assembleDebug :app:bundleRelease
```

## GitHub Actions — exactly one automatic workflow

The repository contains exactly one workflow file: `.github/workflows/main.yml`. It runs automatically on pushes to `main`, retains manual `workflow_dispatch` as a fallback, and uses `concurrency` with `cancel-in-progress: true` so a newer push replaces an older in-progress build instead of creating a pile of simultaneous builds.

If this project is copied over an older repository, remove old YAML files already committed under `.github/workflows/` once; copying new files does not delete old repository files.

See also `docs/RELEASE_CHECKLIST.md`, `docs/RELEASE_SIGNING.md`, `docs/PRIVACY_POLICY_DRAFT.md`, and `docs/CLOUD_REPUTATION.md`.
