# Phase 8 — release hardening

Phase 8 turns the staged project into the `1.0.0` release candidate without pretending Android can provide unrestricted desktop-style antivirus control.

## Security hardening

- Target and compile SDK 36.
- Cleartext networking disabled at the Android network-security layer.
- Threat updates remain HTTPS-only and are authenticated by the existing signed database manifest.
- Release builds enable R8 minification and resource shrinking and explicitly disable debugging.
- Android release signing material is injected from environment variables/GitHub secrets and is never included in the project archive.
- Backup remains disabled and broad storage permissions remain absent.

## False-positive control

- Heuristic `HIGH` thresholds for installed apps, static APK analysis, and link analysis are raised to 55/100.
- A single suspicious filename pattern or an unparsable APK can still appear in manual review, but no longer creates a background high-risk notification by itself.
- Exact signed threat matches continue to override heuristics.

## Performance and battery

- Package installation/update scanning remains event driven.
- Protected-folder periodic checks run every 60 minutes instead of every 15 minutes.
- Periodic checks require battery-not-low and storage-not-low conditions.
- Retry work uses exponential backoff.
- Existing file-size, traversal, APK archive, and DEX-scan bounds remain in place.

## User-facing release polish

- Adaptive launcher icons.
- Explicit light and dark resource palettes.
- App version and threat-database freshness are visible in the threat-intelligence card.
- Arabic and English remain resource-isolated and are validated by the localization gate.

## CI/release

GitHub Actions now validates source/security gates, unit tests, release lint, debug APK, and release Android App Bundle. A configured upload key produces a signed AAB and the workflow verifies its signature. Without signing secrets, the AAB remains a validation artifact only.
