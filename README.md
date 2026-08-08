# Aman Security — Phase 3

Android security scanner with strict Arabic/English UI separation, signed threat-database updates, file/APK scanning, and local installed-app risk review.

## Phase 3 features

- Everything from Phase 2 remains in place.
- User-triggered scan of user-installed Android apps.
- Installed app inventory is processed locally on the device and is not uploaded.
- System packages and Aman Security itself are excluded from the user-app review list.
- Checks requested permissions, declared accessibility services, and install-source category.
- Calculates the installed base package SHA-256 fingerprint and compares it with the active signed threat database.
- Calculates the signing-certificate SHA-256 fingerprint for technical review and later reputation features.
- Risk scoring emphasizes suspicious combinations instead of labeling a normal permission as malware.
- A known local threat-database hash overrides heuristic scoring and is classified as a known threat.
- Prominent first-use disclosure before the installed-app inventory is scanned.
- The UI shows only apps that need review; low-indicator apps are counted in the summary without creating noise.
- Strict Arabic and English resources with an automated localization gate.

## Package visibility

Phase 3 declares `android.permission.QUERY_ALL_PACKAGES` because broad installed-app visibility is part of the core antivirus/security function. Installed-app data stays on-device. Before Google Play publication, complete the package-visibility permission declaration and keep the store disclosure/privacy policy aligned with the in-app disclosure. See:

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

GitHub Actions runs the checks, unit tests, and Android build automatically and uploads `AmanSecurity-Phase3-APK` as the build artifact.
