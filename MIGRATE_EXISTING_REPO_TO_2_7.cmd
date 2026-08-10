@echo off
setlocal
cd /d "%~dp0"

git rev-parse --is-inside-work-tree >nul 2>nul
if errorlevel 1 (
  echo ERROR: Run this file from the root of an existing Git clone after copying Aman 2.7 files into it.
  exit /b 1
)

python tools\repository_cleanup_2_6.py --apply
if errorlevel 1 exit /b 1

python tools\quality_gate.py
if errorlevel 1 exit /b 1

git add -A
if errorlevel 1 exit /b 1

echo.
echo MIGRATION_2_7_READY
ECHO Legacy threat-update files were removed, the automatic build workflow was preserved, and all changes were staged.
echo Review with: git status
echo Then commit and push to main to start the automatic build.
endlocal
