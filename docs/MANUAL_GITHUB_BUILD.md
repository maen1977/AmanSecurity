# GitHub build for Aman Security 2.7

The repository contains exactly one GitHub Actions workflow: `.github/workflows/build.yml`. It is **build/verification only**. Threat intelligence is refreshed by the Android app itself, not by GitHub.

The workflow starts automatically on every push to `main` and can also be started manually with `workflow_dispatch`. It has no scheduled trigger, no threat-intelligence refresh job, no API keys, and no threat-update signing secrets.

## Automatic build

Commit and push the 2.7 project to `main`. GitHub starts **Build Aman Security** automatically. A successful run uploads:

- `AmanSecurity-2.9.0-Debug-APK` — installable test APK.
- `AmanSecurity-2.9.0-Unsigned-Release-AAB` — release bundle that still requires normal Android release signing/distribution configuration.
- `AmanSecurity-2.9.0-Verification-Reports` — unit/lint/dependency reports and artifact SHA-256 checksums when available.

## Manual build

Open **Actions → Build Aman Security → Run workflow**, choose `main`, and run it. Manual dispatch is optional; it is not required after a normal push to `main`.
