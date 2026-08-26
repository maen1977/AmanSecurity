# GitHub Actions threat updates

Aman Security uses `.github/workflows/build.yml` for both the signed threat-intelligence factory and Android CI. The workflow runs on pushes to `main`, on manual dispatch, and once daily at 03:17 UTC. Scheduled runs publish intelligence without rebuilding the Android APK; push and manual runs also build and test the app.

## Secrets

The workflow requires one Actions secret:

- `AMAN_THREAT_DB_PRIVATE_KEY_B64`: base64-encoded RSA private key corresponding to `app/src/main/assets/keys/aman-threat-db-public.pem`. It is used only on the ephemeral CI runner to sign the manifest.

Publication uses the workflow's built-in `GITHUB_TOKEN`, which is granted `contents: write` for this repository and is used only to update the package-only `aman-threat-db` branch. No long-lived cross-repository publish token is required.

`ABUSECH_AUTH_KEY` is optional and enables authenticated MalwareBazaar/ThreatFox enrichment. The factory still has non-authenticated public sources when this secret is absent. No secret is bundled in the APK.

## Update sequence

The workflow checks that the signing secret is present. It then fetches bounded provider metadata, normalizes indicators, discards raw provider payloads, builds the compact seven-file mobile ZIP, signs and verifies the manifest, and force-publishes only `latest/` to the package-only `aman-threat-db` branch using the built-in workflow token. The Android and Windows clients download only the manifest, signature, and a newer signed package from the narrow public endpoint:

```text
https://raw.githubusercontent.com/maen1977/AmanSecurity/aman-threat-db/latest
```

The client verifies the RSA signature, rejects rollback serials, checks exact package names, sizes, hashes, and counts, and swaps the verified staging directory atomically. The last-known-good database remains active if a download, signature, package, or source update fails.

## Repository permissions

The source workflow uses `contents: write` only so it can update the package-only `aman-threat-db` branch. That branch contains no application source, API credentials, private signing material, raw malicious URLs, or malware binaries.

## Source-health behavior

External feeds are attempted independently. A transient provider failure is recorded in the signed build report while successful sources continue to update the package. The mobile package contains only normalized SHA-256 indicators and Android bulletin identifiers. It cannot add executable code, Kotlin/DEX rules, or dynamically loaded detection engines. A signed package remains acceptable only when its manifest, signature, size, hashes, schema, and rollback constraints pass on the device.

## Validation

After a manual run, verify that the `aman-threat-db` branch contains `latest/manifest.json`, `latest/manifest.sig`, `latest/aman-threat-db-{RUN_ID}.zip` (the exact name is referenced by `manifest.json`), and `latest/build-report.json`. Also verify that the two metadata URLs return HTTP 200 without authentication and inspect the uploaded diagnostics artifact before installing the resulting release.
