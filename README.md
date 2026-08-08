# Aman Security — Phase 7

Android security scanner with strict Arabic/English UI separation, signed threat-database updates, file/APK scanning, installed-app risk review, encrypted quarantine, exact-hash exclusions, local scan history, on-device link scanning, bounded APK static analysis, and conservative semi-real-time protection.

## Phase 7 features

- Everything from Phases 1–6 remains in place.
- Optional background protection is disabled until the user explicitly enables it after a disclosure.
- Newly installed or updated user apps trigger an expedited local scan through WorkManager.
- Background app alerts are limited to `HIGH` or exact `KNOWN_THREAT` results; medium-risk permission combinations do not create noisy notifications.
- Installed-app scanning now also checks signed package-name and signer-certificate identity indicators from threat-database schema 3.
- The user may choose one protected folder through Android's Storage Access Framework.
- The selected folder receives bounded checks for new or changed files at WorkManager's 15-minute minimum periodic interval; Android may defer runs.
- The protected-folder scanner reuses the signed signature database and Phase 6 APK static analyzer.
- Exact SHA-256 exclusions suppress a background file alert without changing the underlying detection.
- Android 13+ notification permission is requested only when background protection is enabled.
- Recent background alerts are stored locally and can be cleared by the user.
- Background protection never deletes, quarantines, opens, executes, uploads, or uninstalls anything automatically.
- No broad storage permission is requested.
- Arabic and English remain separated through resource-only user-facing text plus the localization gate.

See:

`docs/PHASE7_BACKGROUND_PROTECTION.md`

## Signed threat database

The app expects these files at the configured HTTPS update location:

- `threat-db/manifest.json`
- `threat-db/manifest.sig`
- `threat-db/signatures.csv`
- `threat-db/url_indicators.csv`
- `threat-db/apk_indicators.csv`

Threat database schema 3 remains active in Phase 7. The private RSA signing key is intentionally **not** included in this project. Only the public verification key is bundled in the Android app.

To publish a future signed update:

```bash
python3 tools/sign_threat_db.py \
  --private-key /safe/offline/path/AmanSecurity_Phase2_UpdateSigning_PrivateKey.pem \
  --serial 5 \
  --version 2026.08.08.4 \
  --min-app-version-code 7
python3 tools/verify_threat_db.py
```

Never commit the private key.

## Quality checks

```bash
python3 tools/verify_localization.py
python3 tools/verify_threat_db.py
python3 tools/quality_gate.py
gradle :app:testDebugUnitTest
gradle :app:assembleDebug
```

GitHub Actions runs the checks, unit tests, and Android build and uploads `AmanSecurity-Phase7-APK` as the build artifact.
