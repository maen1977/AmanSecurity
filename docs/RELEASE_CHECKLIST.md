# Aman Security 2.7 release checklist

- Run `python3 tools/quality_gate.py`.
- Require the automatic GitHub build on `main` to finish green: unit tests, `lintRelease`, debug APK, and release AAB.
- Review the uploaded verification reports and `build-artifact-sha256.txt`.
- Build/sign production distribution artifacts in a trusted environment. Never commit a keystore/private signing key.
- Configure `AMAN_RELEASE_CERT_SHA256` with the public app-signing certificate fingerprint for the production build when signer pinning is desired.
- Confirm no API key, private update key, APK malware sample, DEX payload, executable, keystore, or other secret is bundled.
- Verify Arabic and English UI independently.
- Test autonomous updates on Wi-Fi/mobile data, partial source failure, stale-source TTL, and offline retry.
- Test install and app-update event scanning with background protection enabled.
- Test Web Guard known-block, review-only community indicator, and external-browser forwarding.
- Test quarantine/restore/delete and exclusions; no destructive action should occur automatically.
- For real-world detection claims, use an isolated independently reviewed corpus and export only verdict metadata to `benchmarks/reviewed_detection_results.csv`.
- Do not present internal regression metrics as real-world antivirus certification.
