# Aman Security 2.6 release checklist

- Run `python3 tools/quality_gate.py`.
- Run Android unit tests and `lintRelease` with Android SDK 36.
- Build the release AAB/APK in a trusted build environment.
- Use normal Android release signing for distribution. This signing material is unrelated to autonomous threat-intelligence updates.
- Confirm `.github/` is absent.
- Confirm no API key, private threat-update key, APK malware sample, DEX payload, keystore, or other secret is bundled.
- Verify Arabic and English UI separately.
- Test autonomous updates on Wi-Fi and mobile data, including partial source failure and offline retry.
