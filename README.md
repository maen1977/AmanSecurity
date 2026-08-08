# Aman Security — Phase 5

Android security scanner with strict Arabic/English UI separation, signed threat-database updates, file/APK scanning, installed-app risk review, encrypted quarantine, exact-hash exclusions, local scan history, and on-device link/phishing-risk scanning.

## Phase 5 features

- Everything from Phases 1–4 remains in place.
- Paste/type a web link and scan it without opening the destination.
- Share a text link from another Android app to Aman Security for an immediate local scan.
- The app deliberately does **not** register as a browser and does not intercept normal browsing.
- Signed threat-database schema 2 covers both file indicators and link/host indicators.
- URL and host indicators are stored as SHA-256 hashes rather than live malicious URLs.
- Exact signed URL/host matches override heuristic scoring.
- Local phishing-risk heuristics combine several signals; one weak signal alone is not treated as proof of phishing.
- Only standard HTTP/HTTPS web links are accepted by the link scanner.
- Link scans stay on-device. No URL is sent to a cloud reputation service.
- Arabic and English remain separated through resource-only UI text plus the localization quality gate.

See the Phase 5 design in:

`docs/PHASE5_URL_PROTECTION.md`

## Earlier security layers

- Installed-app review from Phase 3 remains local-only and uses `QUERY_ALL_PACKAGES` for the core antivirus function.
- Phase 4 quarantine remains user-triggered, AES-GCM encrypted, Android-Keystore backed, and requires successful source removal before reporting quarantine success.
- Exact SHA-256 exclusions preserve the underlying detection result.
- File scan history remains local-only and capped.

## Threat database update URL

The Android app is configured for:

`https://raw.githubusercontent.com/maen1977/AmanSecurity/main/threat-db/`

For Phase 5 the repository must expose these four database payload files plus the signature:

- `threat-db/manifest.json`
- `threat-db/manifest.sig`
- `threat-db/signatures.csv`
- `threat-db/url_indicators.csv`

The manifest signature covers the hashes and metadata for both databases.

## Important signing-key rule

The private RSA update-signing key is intentionally **not** inside this project. Keep it offline. Only the public key in `app/src/main/assets/keys/` is bundled in the app.

To publish a future database update:

```bash
python3 tools/sign_threat_db.py \
  --private-key /safe/offline/path/AmanSecurity_Phase2_UpdateSigning_PrivateKey.pem \
  --serial 4 \
  --version 2026.08.08.3 \
  --min-app-version-code 5
python3 tools/verify_threat_db.py
```

Commit only the signed database payloads and signature. Never commit the private key.

## Safe bundled URL test indicators

The bundled Phase 5 link database contains only SHA-256 hashes corresponding to reserved `.test` values. They exist to exercise the signed URL-detection path without shipping or opening a live malicious site. Production phishing/malware indicators should be reviewed, hashed offline, then published through a newly signed database release.

## Quality checks

```bash
python3 tools/verify_localization.py
python3 tools/verify_threat_db.py
python3 tools/quality_gate.py
gradle :app:testDebugUnitTest
gradle :app:assembleDebug
```

GitHub Actions runs the checks, unit tests, and Android build automatically and uploads `AmanSecurity-Phase5-APK` as the build artifact.
