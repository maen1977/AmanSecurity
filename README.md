# Aman Security — Phase 6

Android security scanner with strict Arabic/English UI separation, signed threat-database updates, file/APK scanning, installed-app risk review, encrypted quarantine, exact-hash exclusions, local scan history, on-device link scanning, and bounded advanced APK static analysis.

## Phase 6 features

- Everything from Phases 1–5 remains in place.
- Selected APK files receive a second local static-analysis pass without installation or execution.
- Android package metadata, requested permissions, declared high-impact components, certificate identity, archive structure, code-file count, native-library count, and selected code markers are reviewed.
- A bounded risk model combines several indicators; isolated ordinary permissions do not become malware verdicts.
- Threat database **schema 3** adds signed package-name and signer-certificate identity indicators.
- Exact signed identity matches can survive a changed APK file hash when the reviewed signing/package identity remains the same.
- Bundled Phase 6 identity rows are harmless test signatures only.
- Temporary analysis copies stay in app cache, are re-hashed against the selected source, and are deleted after analysis.
- Static APK analysis is local-only and performs no cloud upload or reputation lookup.
- Arabic and English remain separated through resource-only user-facing text plus the localization gate.

See the security design in:

`docs/PHASE6_ADVANCED_APK_ANALYSIS.md`

## Signed threat database

The app expects these files at the configured HTTPS update location:

- `threat-db/manifest.json`
- `threat-db/manifest.sig`
- `threat-db/signatures.csv`
- `threat-db/url_indicators.csv`
- `threat-db/apk_indicators.csv`

Schema 3 signs the SHA-256 and metadata for all three indicator databases. Phase 6 refuses an older schema update so link and APK-identity protection cannot be silently downgraded.

## Update-signing key rule

The private RSA signing key is intentionally **not** included in this project. Keep it offline. Only the public verification key is bundled in the Android app.

To publish a future signed update:

```bash
python3 tools/sign_threat_db.py \
  --private-key /safe/offline/path/AmanSecurity_Phase2_UpdateSigning_PrivateKey.pem \
  --serial 5 \
  --version 2026.08.08.4 \
  --min-app-version-code 6
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

GitHub Actions runs the checks, unit tests, and Android build and uploads `AmanSecurity-Phase6-APK` as the build artifact.
