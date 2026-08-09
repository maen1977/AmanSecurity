# GitHub Actions threat-intelligence updates

Aman Security uses one workflow file, `.github/workflows/main.yml`, for both threat refresh and Android CI.

## Schedule

The workflow runs automatically every six hours and on pushes to `main`. `concurrency.cancel-in-progress` ensures a newer run replaces an older in-progress run for the same ref.

## Secrets

### Threat intelligence

`THREAT_DB_PRIVATE_KEY_BASE64` must contain the base64-encoded RSA private key corresponding to `app/src/main/assets/keys/threat_update_public_key.pem`. The workflow decodes it only into the GitHub runner temporary directory and deletes it when the runner is destroyed.

`ABUSECH_AUTH_KEY` enables MalwareBazaar and URLhaus indicator imports. `PHISHING_FEED_URL` is optional and must be an HTTPS feed whose terms allow your use.

### Release signing

The Android release upload key remains separate from the threat-intelligence signing key and uses the `ANDROID_KEYSTORE_*` secrets documented in `RELEASE_SIGNING.md`.

## Update sequence

1. Checkout.
2. Decode threat DB signing key into the runner temp directory.
3. Import metadata/indicators only; never request malware sample binaries.
4. Compact/deduplicate bounded mobile databases.
5. Increment DB serial only when indicator content changed.
6. Sign the threat DB manifest.
7. Synchronize the same signed DB into Android assets.
8. Generate and sign SHA-256 prefix reputation shards.
9. Verify all signatures and hashes.
10. Commit only `threat-db`, `reputation`, and bundled threat assets if changed.
11. Build/test the Android app using exactly the refreshed data from the same workflow run.

A commit made by the workflow uses the repository `GITHUB_TOKEN`; GitHub prevents that token-generated push from recursively starting another normal workflow run, avoiding an update loop.

## Repository permissions

The workflow default is `contents: read`. Only the `refresh-threat-intelligence` job requests `contents: write` so it can commit signed indicator updates.

If branch protection prevents the Actions bot from pushing to `main`, allow the workflow's GitHub Actions identity to update the threat-data paths or use a reviewed pull-request process instead.
