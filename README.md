# Aman Security 2.6.0

Android antivirus / anti-malware project with Arabic and English UI, on-device APK/app analysis, phishing protection, Web Guard, encrypted quarantine, continuous installed-app rescans, behavior/zero-day heuristics, and autonomous threat-intelligence updates.

## 2.6 autonomous intelligence

The app itself refreshes public no-key threat intelligence about every six hours when Android permits background work and the network is connected. GitHub Actions are not used and the project contains no `.github` automation directory. No API keys or threat-update private keys are required.

The updater downloads only text/JSON/HTML indicators from fixed HTTPS sources, rejects executable/archive payloads, validates and stages each source independently, keeps the last valid source data on failure, and triggers an installed-app rescan after a successful refresh when background protection is enabled.

See `docs/AUTONOMOUS_THREAT_INTELLIGENCE_2_6.md` for the source and safety model.

## Development checks

```bash
python3 tools/quality_gate.py
```

Full Android unit tests, lint, APK/AAB building and release signing should be run in Android Studio or a trusted build environment with Android SDK 36.
