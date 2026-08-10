@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo Aman Security 2.6 - remove legacy GitHub Actions permanently
echo ============================================================
echo.

if not exist ".git" (
  echo ERROR: This folder is not the root of your local Git clone.
  echo Copy/extract the Aman 2.6 files into the existing AmanSecurity Git folder,
  echo then run this file again from that folder.
  exit /b 1
)

echo [1/4] Removing legacy workflow and signed-reputation pipeline...
if exist ".github" rmdir /s /q ".github"
if exist "reputation" rmdir /s /q "reputation"

for %%F in (
  "tools\threat_db_continuity_gate.py"
  "tools\reviewed_reputation_gate.py"
  "tools\threat_intel_quality_gate.py"
  "tools\reputation_gate.py"
  "tools\verify_reputation_shards.py"
  "tools\single_workflow_gate.py"
  "tools\detection_gate.py"
  "tools\real_antivirus_gate.py"
  "tools\release_gate.py"
  "tools\build_reputation_shards.py"
  "tools\refresh_threat_intel.py"
  "tools\update_threat_intel.py"
  "tools\sign_threat_db.py"
  "tools\threat_source_health_gate.py"
  "tools\continuous_protection_gate.py"
  "tools\threat_reputation_2_3_gate.py"
) do (
  if exist "%%~F" del /f /q "%%~F"
)

echo [2/4] Recording deletions in Git...
git add -A
if errorlevel 1 (
  echo ERROR: git add failed.
  exit /b 1
)

echo [3/4] Verifying the exact files that caused the old Action are gone...
if exist ".github\workflows\main.yml" (
  echo ERROR: .github\workflows\main.yml still exists.
  exit /b 1
)
if exist "tools\threat_db_continuity_gate.py" (
  echo ERROR: tools\threat_db_continuity_gate.py still exists.
  exit /b 1
)

findstr /s /i /m "minimumSignedReputationEntries" *.py *.json *.yml *.yaml 2>nul > "%TEMP%\aman_legacy_refs.txt"
for %%A in ("%TEMP%\aman_legacy_refs.txt") do if %%~zA GTR 0 (
  echo ERROR: Found legacy minimumSignedReputationEntries reference:
  type "%TEMP%\aman_legacy_refs.txt"
  del /q "%TEMP%\aman_legacy_refs.txt" >nul 2>&1
  exit /b 1
)
del /q "%TEMP%\aman_legacy_refs.txt" >nul 2>&1

echo [4/4] Staged Git changes:
git status --short

echo.
echo ============================================================
echo CLEANUP READY

echo The old workflow and threat_db_continuity_gate.py are deleted.
echo Now run these TWO commands:
echo.
echo   git commit -m "migrate: remove legacy GitHub Actions for Aman 2.6"
echo   git push origin main
echo.
echo Do NOT re-run the old failed GitHub Action.
echo After the push, no automatic GitHub Action should start.
echo ============================================================
exit /b 0
