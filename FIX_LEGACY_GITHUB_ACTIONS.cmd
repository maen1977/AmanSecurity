@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if not exist ".git" (
  echo ERROR: This folder is not the root of your local Git clone.
  exit /b 1
)

echo Removing old threat-update workflows while keeping build.yml...
if exist ".github\workflows" (
  for %%F in (".github\workflows\*.yml" ".github\workflows\*.yaml") do (
    if exist "%%~F" if /I not "%%~nxF"=="build.yml" del /f /q "%%~F"
  )
)

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
) do (
  if exist "%%~F" del /f /q "%%~F"
)

git add -A
if errorlevel 1 exit /b 1

if not exist ".github\workflows\build.yml" (
  echo ERROR: build.yml is missing.
  exit /b 1
)
if exist ".github\workflows\main.yml" (
  echo ERROR: legacy main.yml still exists.
  exit /b 1
)

echo.
echo CLEANUP READY - build.yml preserved.
echo Now run:
echo   git commit -m "build: add manual Aman build workflow"
echo   git push origin main
exit /b 0
