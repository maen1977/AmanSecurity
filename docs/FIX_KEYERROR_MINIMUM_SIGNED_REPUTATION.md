# Fix for KeyError: minimumSignedReputationEntries

If GitHub Actions prints:

`KeyError: 'minimumSignedReputationEntries'`

then the repository still contains the pre-2.6 workflow and gate. Aman 2.6 no longer uses signed GitHub reputation updates, so the correct fix is deletion, not adding the old config key back.

On Windows, from the root of the existing local Git clone, run:

`FIX_LEGACY_GITHUB_ACTIONS.cmd`

This CMD file is not affected by PowerShell ExecutionPolicy. It removes `.github`, the old `tools/threat_db_continuity_gate.py`, and the remaining pre-2.6 signed-reputation/update gates, then stages those deletions with `git add -A`.

After it reports `CLEANUP READY`, run:

`git commit -m "migrate: remove legacy GitHub Actions for Aman 2.6"`

`git push origin main`

Do not re-run the old failed Action. Historical failed runs may remain visible in GitHub Actions, but no new automatic workflow should start after the deletion commit.
