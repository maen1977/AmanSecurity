# Aman Security 3.5 — Cloud Intelligence Factory

## Architecture

**GitHub Actions is the intelligence factory. Aman on Android is the lightweight consumer and scanner.**

The workflow runs the intelligence factory once daily at 03:17 UTC. It gathers bounded threat-indicator feeds, normalizes them in CI, converts URLs/hosts to SHA-256 indicators, discards raw provider payloads, creates a compact ZIP, signs the manifest, verifies the package, and force-publishes only the latest package to the dedicated public `aman-threat-db` branch of this repository. The branch contains package artifacts only; the normal source tree remains on `main`.

The Android app never parses the upstream provider feeds. It downloads only `manifest.json`, `manifest.sig`, and—only for a newer serial—the compact `aman-threat-db-{RUN_ID}.zip` package named by the manifest from the configured Aman endpoint. It verifies the RSA signature before trusting package metadata, rejects rollback serials, streams the ZIP to disk, checks exact file names/sizes/hashes/counts, and swaps a verified staging directory into service atomically. The previous database remains active if any step fails.

## Low-memory design

- No raw provider payloads are parsed on the phone.
- No large threat feed is materialized as one giant Java/Kotlin `String`.
- SHA-256 indexes are sorted fixed-width files and use read-only `MappedByteBuffer` binary search.
- Update I/O uses 32 KiB buffers.
- The signed mobile bundle is capped at 24 MiB.
- Periodic update work requires an unmetered network and battery-not-low and runs about every 24 hours within a 120-minute flex window after a device-specific initial delay; manual update only requires connectivity.
- Immutable malware file hashes remain usable if web intelligence later becomes stale; transient URL/C2 intelligence has bounded freshness.

## Published package

The branch contains only:

- `latest/manifest.json`
- `latest/manifest.sig`
- `latest/aman-threat-db-{RUN_ID}.zip` (the exact name is referenced by `manifest.json`)
- `latest/build-report.json`

The mobile ZIP contains only compact indicator indexes and Android CVE identifiers. It does not contain raw malicious URLs or malware binaries.

## GitHub secrets

Required for publishing:

- `AMAN_THREAT_DB_PRIVATE_KEY_B64` — base64-encoded private RSA signing key. Never commit it to the repository or place it in the APK.
- The workflow's built-in `GITHUB_TOKEN` — granted `contents: write` in this repository and used only to force-update the package-only `aman-threat-db` branch. No long-lived cross-repository publish token is required.

Optional enrichment:

- `ABUSECH_AUTH_KEY` — enables authenticated MalwareBazaar/ThreatFox API enrichment. The factory still has non-authenticated/public sources when this secret is absent.

The matching **public** RSA key is intentionally bundled at `app/src/main/assets/keys/aman-threat-db-public.pem` so the app can verify manifests offline.

## First deployment

1. Add `AMAN_THREAT_DB_PRIVATE_KEY_B64` in **Repository Settings → Secrets and variables → Actions**. The workflow already declares `contents: write` for its built-in token.
2. Optionally add `ABUSECH_AUTH_KEY`.
3. Run **Aman Security Pipeline** manually once.
4. Confirm the package-only `aman-threat-db` branch contains `latest/manifest.json`, `latest/manifest.sig`, and the dynamic `latest/aman-threat-db-{RUN_ID}.zip` referenced by the manifest.
5. Confirm these anonymous URLs return HTTP 200: `https://raw.githubusercontent.com/maen1977/AmanSecurity/aman-threat-db/latest/manifest.json` and `https://raw.githubusercontent.com/maen1977/AmanSecurity/aman-threat-db/latest/manifest.sig`.
6. The normal Android and Windows builds embed `https://raw.githubusercontent.com/maen1977/AmanSecurity/aman-threat-db/latest`, and their client allowlists accept only this host, owner, repository, branch, and `latest` directory.
7. Install the generated release and run **Settings → Protection updates → Update protection now**.

The mobile client uses anonymous HTTPS, so only the signed package branch is consumed. The private signing key remains a GitHub Actions secret and is never placed in the APK or package branch.

## Validation

Run:

```bash
python3 tools/quality_gate.py
python3 tools/verify_single_workflow.py
```

`tools/cloud_intelligence_factory_3_5_gate.py` also builds a deterministic harmless offline fixture and checks that no raw HTTP/HTTPS URL leaks into the mobile ZIP.
