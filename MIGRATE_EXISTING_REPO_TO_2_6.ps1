$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.git')) {
    Write-Host 'ERROR: Run this script from the root of your local AmanSecurity Git clone.' -ForegroundColor Red
    exit 1
}

Write-Host 'Aman 2.6 migration: removing legacy GitHub Actions and signed-reputation pipeline...' -ForegroundColor Cyan

python3 tools/repository_cleanup_2_6.py --apply
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Remove any tracked legacy paths even if they were already absent from the extracted 2.6 ZIP.
$legacy = @(
    '.github',
    'reputation',
    'tools/threat_db_continuity_gate.py',
    'tools/reviewed_reputation_gate.py',
    'tools/threat_intel_quality_gate.py',
    'tools/reputation_gate.py',
    'tools/verify_reputation_shards.py',
    'tools/single_workflow_gate.py',
    'tools/detection_gate.py',
    'tools/real_antivirus_gate.py',
    'tools/release_gate.py',
    'tools/build_reputation_shards.py',
    'tools/refresh_threat_intel.py',
    'tools/update_threat_intel.py',
    'tools/sign_threat_db.py'
)

foreach ($path in $legacy) {
    git rm -r --ignore-unmatch -- $path 2>$null | Out-Null
}

python3 tools/autonomous_continuity_gate.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python3 tools/autonomous_threat_intel_2_6_gate.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python3 tools/quality_gate.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$workflowFiles = @(Get-ChildItem -Path '.github/workflows' -File -ErrorAction SilentlyContinue)
if ($workflowFiles.Count -gt 0) {
    Write-Host 'ERROR: GitHub workflow files still exist:' -ForegroundColor Red
    $workflowFiles | ForEach-Object { Write-Host $_.FullName }
    exit 1
}

Write-Host ''
Write-Host 'MIGRATION_2_6_READY: GitHub Actions = 0 and autonomous gates passed.' -ForegroundColor Green
Write-Host 'Now review `git status`, then run:'
Write-Host '  git add -A'
Write-Host '  git commit -m "migrate: Aman 2.6 autonomous threat intelligence"'
Write-Host '  git push'
