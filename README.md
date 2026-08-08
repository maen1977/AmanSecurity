# Aman Security 1.0.0 — Release Candidate

A bilingual Android security scanner with strict Arabic/English UI separation, cryptographically signed threat-database updates, file/APK scanning, installed-app risk review, encrypted quarantine, exact-hash exclusions, local scan history, on-device link analysis, bounded APK static analysis, and conservative background protection.

## Phase 8 / release hardening

- Production version `1.0.0` (`versionCode 8`) targeting Android 16 / API 36.
- Release R8 minification and resource shrinking.
- Cleartext networking disabled through Android network-security configuration.
- Adaptive launcher icon plus explicit light/dark resources.
- Threat-database freshness shown in the UI without claiming that a clean result guarantees safety.
- More conservative heuristic thresholds: isolated indicators remain review context, while known signed indicators continue to override heuristics.
- Background file notifications suppress low-confidence reasons such as a double extension or unparsable APK; confirmed signatures and high static-risk APK combinations still alert.
- Protected-folder periodic scanning is battery/storage aware and runs on a one-hour WorkManager cadence; package-install scans remain event driven.
- Release signing is injected only from environment/GitHub secrets; no Android private signing key is included.
- CI runs localization/database/source/release gates, unit tests, release lint, debug APK build, and release AAB build.
- Dependabot configuration tracks Gradle and GitHub Actions updates.
- Release checklist, signing guide, and privacy-policy draft are included under `docs/`.

## Build checks

```bash
python3 tools/verify_localization.py
python3 tools/verify_threat_db.py
python3 tools/quality_gate.py
python3 tools/release_gate.py
gradle :app:testDebugUnitTest :app:lintRelease :app:assembleDebug :app:bundleRelease
```

When GitHub release-signing secrets are configured, the AAB is signed with the upload key and verified by `jarsigner`. Without those secrets the source remains fully buildable, but the release AAB is unsigned and is not Play-upload ready.

See `docs/RELEASE_CHECKLIST.md`, `docs/RELEASE_SIGNING.md`, and `docs/PRIVACY_POLICY_DRAFT.md`.

## GitHub Actions: single workflow policy

This release contains exactly one workflow file: `.github/workflows/main.yml`.
It is manual-only (`workflow_dispatch`) so pushes/uploads do not create a large list of automatic workflow runs. Start it from GitHub **Actions → Build Aman Security Android → Run workflow**.
The workflow also has a concurrency guard and cancels an older in-progress build if a newer manual build is started.

Important: uploading these files over an existing repository does not delete old workflow YAML files already committed on GitHub. Before running this release, remove every old `.yml`/`.yaml` under `.github/workflows/` except `main.yml` once.
