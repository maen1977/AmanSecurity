# Aman Security 3.3 Rev3.3.2 — Direct Install Fix

This revision keeps the security engine intact while making the GitHub test build easier and safer to install directly on Android.

Changes:
- GitHub Actions now publishes a normal single APK named `AmanSecurity-3.3.0-DirectInstall.apk`.
- The CI debug keystore is cached so test builds from the same repository are less likely to change signing identity between runs.
- Banking Guard AccessibilityService is disabled at install time and only enabled after the user explicitly enables Banking Protection and confirms the disclosure.
- Turning Banking Protection off disables that component again.
- No verifier/Play Protect/Android security check is bypassed.

Install the generated APK with Android's normal Package Installer after extracting the GitHub Actions artifact once. SAI is not required for this APK.
