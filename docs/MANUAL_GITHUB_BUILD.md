# Aman 2.6 build workflow

The single GitHub Actions workflow is **build-only**. It runs automatically on every push to `main` and can also be started manually with `workflow_dispatch`. It has no schedule, no threat-intelligence refresh job, and no API keys or signing secrets for threat updates. Threat intelligence updates remain inside the Android app.

# Manual GitHub build for Aman Security 2.6

Aman 2.6 does not use GitHub Actions for threat-intelligence updates. Threat intelligence is refreshed by the Android app itself.

The repository contains exactly one GitHub workflow:

- `.github/workflows/build.yml`
- trigger: `workflow_dispatch` only
- purpose: test/lint/build the Android app
- no schedule
- no API keys
- no threat-update secrets
- read-only repository permission

## Run it

1. Commit and push `.github/workflows/build.yml` to the repository default branch (`main`).
2. Open the repository on GitHub.
3. Open **Actions**.
4. Select **Build Aman Security**.
5. Click **Run workflow**, select `main`, then **Run workflow**.
6. After the build succeeds, open the run and download the artifact `AmanSecurity-2.6.0-Debug-APK`.

The debug APK is signed with the normal debug signing identity produced by the Android build tools and is suitable for installing/testing. The release AAB artifact is intentionally unsigned because Aman does not store a release signing key in the repository or GitHub Secrets.
