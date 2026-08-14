# GitHub Actions threat updates

Aman Security uses `.github/workflows/build.yml` for both the signed threat-intelligence factory and Android CI. The workflow runs on pushes to `main`, on manual dispatch, and once daily at 03:17 UTC. Scheduled runs publish intelligence without rebuilding the Android APK; push and manual runs also build and test the app.

## Secrets

The private `AmanSecurity` repository requires the following Actions secrets:

- `AMAN_THREAT_DB_PRIVATE_KEY_B64`: base64-encoded RSA private key corresponding to `app/src/main/assets/keys/aman-threat-db-public.pem`. It is used only on the ephemeral CI runner to sign the manifest.
- `AMAN_THREAT_DEPLOY_KEY`: passwordless SSH private key whose public half is installed as a write-enabled deploy key on the public `maen1977/AmanSecurity-Threat-DB` repository. It is used only to publish the signed package mirror.

`ABUSECH_AUTH_KEY` is optional and enables authenticated MalwareBazaar/ThreatFox enrichment. The factory still has non-authenticated public sources when this secret is absent. No secret is bundled in the APK.

## Update sequence

The workflow checks that both required secrets are present and fails fast when either is missing. The source repository uses read-only contents permission; cross-repository publication is performed through the repository-scoped SSH deploy key, not the source workflow's `GITHUB_TOKEN`. It then fetches bounded provider metadata, normalizes indicators, discards raw provider payloads, builds the compact seven-file mobile ZIP, signs and verifies the manifest, and force-publishes only `latest/` to the public threat-package repository. The Android client downloads only the manifest, signature, and a newer signed package from the narrow public endpoint:

```text
https://raw.githubusercontent.com/maen1977/AmanSecurity-Threat-DB/main/latest
```

The client verifies the RSA signature, rejects rollback serials, checks exact package names, sizes, hashes, and counts, and swaps the verified staging directory atomically. The last-known-good database remains active if a download, signature, package, or source update fails.

## Repository permissions

The private source workflow uses `contents: read`; it does not need write permission in the source repository. The publishing token is scoped to the public threat repository only. The public repository contains no application source, API credentials, private signing material, raw malicious URLs, or malware binaries.

## Source-health behavior

External feeds are attempted independently. A transient provider failure is recorded in the signed build report while successful sources continue to update the package. The mobile package contains only normalized SHA-256 indicators and Android bulletin identifiers. It cannot add executable code, Kotlin/DEX rules, or dynamically loaded detection engines. A signed package remains acceptable only when its manifest, signature, size, hashes, schema, and rollback constraints pass on the device.

## Validation

After a manual run, verify that the public repository contains `latest/manifest.json`, `latest/manifest.sig`, `latest/aman-threat-db-{RUN_ID}.zip (the exact name is referenced by `manifest.json`)`, and `latest/build-report.json`. Also verify that the two metadata URLs return HTTP 200 without authentication and inspect the uploaded diagnostics artifact before installing the resulting APK.
