# Aman Security 3.3 — Direct-install test build

This repository intentionally produces a normal, single APK named `AmanSecurity-3.3.0-DirectInstall.apk` from the GitHub Actions build.

## Why this build exists

- It is a standard APK; SAI/XAPK installers are not required.
- The CI debug keystore is cached with a fixed cache key so normal test updates from the same repository are less likely to fail because a new ephemeral debug certificate was generated on every runner.
- Banking Guard's AccessibilityService component is **disabled at install time**. Aman only enables the component after the user explicitly turns on Banking Protection and confirms the disclosure. This reduces unnecessary privileged surface at installation and follows Android's restricted-settings model more closely.
- No Android verifier, Play Protect, OEM verifier, or developer-verification protection is bypassed or disabled.

## Install

1. Download the GitHub Actions artifact `AmanSecurity-3.3.0-DirectInstall-APK`.
2. Extract the artifact ZIP once.
3. Tap `AmanSecurity-3.3.0-DirectInstall.apk` from Android Files / Package Installer. Do not feed the APK to SAI unless you have a specific reason.
4. If an older CI-debug Aman build was signed by a different ephemeral key, uninstall that old **debug** package once, then install this build. Future builds should reuse the cached test key while the cache remains available.

For production distribution, use a private release signing key and Android developer registration. Do not treat the cached CI debug key as a production identity.


## Rev3.3.3 Play Protect sideload compatibility

Google Play Protect Enhanced Fraud Protection automatically blocks apps installed from internet-sideload sources when they declare certain high-risk capabilities including Accessibility. The direct-install build therefore declares no AccessibilityService, no SMS permissions, and no NotificationListenerService. Banking risk checks remain available as an explicit local **Check now** action. This is a compatibility redesign, not a Play Protect bypass.
