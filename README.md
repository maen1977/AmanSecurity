# Aman Security — Phase 4

Android security scanner with strict Arabic/English UI separation, signed threat-database updates, file/APK scanning, installed-app risk review, encrypted quarantine, exact-hash exclusions, and local scan history.

## Phase 4 features

- Everything from Phases 1–3 remains in place.
- User-triggered quarantine for files that need review.
- Quarantined content is encrypted with AES-GCM in app-private storage using a key generated in Android Keystore.
- Aman recomputes SHA-256 while copying the selected source into quarantine. If it no longer matches the scan, the operation stops.
- The source file is removed only when the document provider grants deletion. If source removal fails, the encrypted copy is discarded and Aman clearly reports that the original remains in place.
- Restore uses Android's document creation flow and verifies SHA-256 again before removing the quarantine copy.
- Permanent delete requires confirmation and removes only the encrypted quarantine copy.
- Exact SHA-256 exclusions. The original threat/suspicion classification remains visible; exclusion only suppresses the quarantine recommendation for that exact hash.
- Local scan history capped at 100 records and clearable independently of quarantine and exclusions.
- No broad external-storage permission.
- Arabic and English remain separated through resource-only UI text plus the localization quality gate.

See the Phase 4 security design in:

`docs/PHASE4_SECURITY_MODEL.md`

## Package visibility

The app declares `android.permission.QUERY_ALL_PACKAGES` because broad installed-app visibility is part of the core antivirus/security function from Phase 3. Installed-app data stays on-device. Before Google Play publication, complete the package-visibility permission declaration and keep the store disclosure/privacy policy aligned with the in-app disclosure. See:

`docs/PLAY_QUERY_ALL_PACKAGES_DECLARATION.md`

## Threat database update URL

The Android app is configured for:

`https://raw.githubusercontent.com/maen1977/AmanSecurity/main/threat-db/`

Upload the project contents to the repository root so that `threat-db/manifest.json`, `threat-db/manifest.sig`, and `threat-db/signatures.csv` are available at that location.

## Important signing-key rule

The private RSA update-signing key is intentionally NOT inside this project. Keep it offline. Only the public key in `app/src/main/assets/keys/` is bundled in the app.

To publish a future database update:

```bash
python3 tools/sign_threat_db.py \
  --private-key /safe/offline/path/AmanSecurity_Phase2_UpdateSigning_PrivateKey.pem \
  --serial 3 \
  --version 2026.08.08.2
python3 tools/verify_threat_db.py
```

Commit only the three files under `threat-db/`. Never commit the private key.

## Quality checks

```bash
python3 tools/verify_localization.py
python3 tools/verify_threat_db.py
python3 tools/quality_gate.py
gradle :app:testDebugUnitTest
gradle :app:assembleDebug
```

GitHub Actions runs the checks, unit tests, and Android build automatically and uploads `AmanSecurity-Phase4-APK` as the build artifact.
