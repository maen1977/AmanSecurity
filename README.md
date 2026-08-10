# Aman Security 2.6.0

Android antivirus / anti-malware project with Arabic and English UI, on-device APK/app analysis, phishing protection, Web Guard, encrypted quarantine, continuous installed-app rescans, behavior/zero-day heuristics, and autonomous threat-intelligence updates.

## 2.6 autonomous intelligence

The app itself refreshes public no-key threat intelligence about every six hours when Android permits background work and the network is connected. GitHub Actions are not used for threat-intelligence updates. The project contains one manual `build.yml` workflow only for compiling/testing the Android app. No API keys or threat-update private keys are required.

The updater downloads only text/JSON/HTML indicators from fixed HTTPS sources, rejects executable/archive payloads, validates and stages each source independently, keeps the last valid source data on failure, and triggers an installed-app rescan after a successful refresh when background protection is enabled.

See `docs/AUTONOMOUS_THREAT_INTELLIGENCE_2_6.md` for the source and safety model.

## Development checks

```bash
python3 tools/quality_gate.py
```

Full Android unit tests, lint, APK/AAB building can be run with the manual GitHub build workflow or Android Studio. Release signing still requires a separate Android signing key; the manual workflow intentionally creates an installable debug APK and an unsigned release AAB without storing secrets.

## Upgrading an older GitHub repository to 2.6

Do not only overlay the ZIP on top of old repository files: Git does not remove
legacy files that are absent from the ZIP. Aman 2.6 has **no GitHub Actions threat-update pipeline**. It keeps exactly one manual build-only workflow (`.github/workflows/build.yml`). If an older `.github/workflows/main.yml` or legacy
reputation gates remain, remove them before committing 2.6. A cleanup helper is
included:

```bash
python3 tools/repository_cleanup_2_6.py        # preview
python3 tools/repository_cleanup_2_6.py --apply
```

See `docs/MIGRATION_2_6_NO_GITHUB_ACTIONS.md`.

For an existing local Git clone, one-time migration launchers are also included at the repository root:

```powershell
./MIGRATE_EXISTING_REPO_TO_2_6.ps1
```

or on Linux/macOS:

```bash
./MIGRATE_EXISTING_REPO_TO_2_6.sh
```

These remove tracked legacy threat-update workflow/reputation files, preserve the manual build workflow, run the autonomous 2.6 gates, and stop before commit/push so the changes can be reviewed.


## If GitHub still reports `minimumSignedReputationEntries`
That log comes from the pre-2.6 workflow left in an existing repository. On Windows run `FIX_LEGACY_GITHUB_ACTIONS.cmd` from the root of the local Git clone, then commit and push the staged deletions. Do not add the old signed-reputation key back; Aman 2.6 intentionally has no GitHub Actions threat-update pipeline.

### 2.6 build migration note
The manual GitHub build removes the legacy pre-2.6 `app/src/main/assets/keys` directory from the runner workspace before quality gates and Android packaging. Aman 2.6 does not use those update keys.
