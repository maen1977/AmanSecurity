$ErrorActionPreference = 'Stop'
if (-not (Test-Path '.git')) { Write-Host 'ERROR: Run from the root of the local AmanSecurity Git clone.' -ForegroundColor Red; exit 1 }
python3 tools/repository_cleanup_2_6.py --apply
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git add -A
python3 tools/quality_gate.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not (Test-Path '.github/workflows/build.yml')) { Write-Host 'ERROR: build.yml missing.' -ForegroundColor Red; exit 1 }
Write-Host 'MIGRATION_2_7_READY: legacy threat-update Actions removed; automatic build workflow preserved.' -ForegroundColor Green
Write-Host 'Now commit and push.'
