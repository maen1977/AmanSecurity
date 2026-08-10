# Aman 2.6 repository migration: no GitHub Actions

Aman 2.6 performs threat-intelligence refreshes on the Android device. The
repository must not retain the old GitHub Actions threat-update pipeline.

## Important when upgrading an existing repository

Uploading/extracting the 2.6 ZIP over an existing Git repository does **not**
delete files that existed only in older releases. In particular, an old
`.github/workflows/main.yml` can remain and continue to run old quality gates.
Those gates expect the retired signed-reputation pipeline and are incompatible
with the autonomous 2.6 layout.

From a local clone, preview the cleanup:

```bash
python3 tools/repository_cleanup_2_6.py
```

Then apply it:

```bash
python3 tools/repository_cleanup_2_6.py --apply
```

Commit the deletions together with the 2.6 files. After that there should be no
`.github` directory in the Aman source tree.

The 2.6 replacement continuity check is:

```bash
python3 tools/autonomous_continuity_gate.py
```

It validates the static APK seed only and has no signed-reputation or API-key
dependency.
