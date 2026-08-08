# Aman Security — Phase 2

Android malware scanner foundation with Arabic/English UI separation and cryptographically signed threat-database updates.

## Phase 2 features

- Local SHA-256 file/APK scanning.
- Bundled signed threat database with harmless EICAR test signature plus seed Android threat hashes.
- User-triggered threat database updates from the repository `threat-db/` folder.
- HTTPS-only update transport.
- RSA/SHA-256 signature verification before an update can be activated.
- SHA-256 content validation, entry-count validation, duplicate rejection, size limits, and rollback protection using a monotonic `serial`.
- Invalid downloaded databases automatically fall back to the bundled verified database.
- No broad storage permission; files are selected through Android's document picker.
- Strict Arabic and English string catalogs with an automated localization gate.

## Update URL

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

Then commit only the three files under `threat-db/`. Never commit the private key.

## Quality checks

```bash
python3 tools/verify_localization.py
python3 tools/verify_threat_db.py
python3 tools/quality_gate.py
```
