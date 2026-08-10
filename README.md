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

## Upgrading an older GitHub repository to 2.6

Do not only overlay the ZIP on top of old repository files: Git does not remove
legacy files that are absent from the ZIP. Aman 2.6 has **no GitHub Actions
threat-update pipeline**. If an older `.github/workflows/main.yml` or legacy
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

These remove tracked legacy workflow/reputation files, run the autonomous 2.6 gates, and stop before commit/push so the deletions can be reviewed.

