#!/usr/bin/env bash
set -euo pipefail

if [[ ! -d .git ]]; then
  echo 'ERROR: Run this script from the root of your local AmanSecurity Git clone.' >&2
  exit 1
fi

echo 'Aman 2.6 migration: removing legacy GitHub Actions and signed-reputation pipeline...'
python3 tools/repository_cleanup_2_6.py --apply

legacy=(
  .github
  reputation
  tools/threat_db_continuity_gate.py
  tools/reviewed_reputation_gate.py
  tools/threat_intel_quality_gate.py
  tools/reputation_gate.py
  tools/verify_reputation_shards.py
  tools/single_workflow_gate.py
  tools/detection_gate.py
  tools/real_antivirus_gate.py
  tools/release_gate.py
  tools/build_reputation_shards.py
  tools/refresh_threat_intel.py
  tools/update_threat_intel.py
  tools/sign_threat_db.py
)
for path in "${legacy[@]}"; do
  git rm -r --ignore-unmatch -- "$path" >/dev/null 2>&1 || true
done

python3 tools/autonomous_continuity_gate.py
python3 tools/autonomous_threat_intel_2_6_gate.py
python3 tools/quality_gate.py

if find .github/workflows -type f -print -quit 2>/dev/null | grep -q .; then
  echo 'ERROR: GitHub workflow files still exist.' >&2
  find .github/workflows -type f -print >&2
  exit 1
fi

echo 'MIGRATION_2_6_READY: GitHub Actions = 0 and autonomous gates passed.'
echo 'Review git status, then: git add -A && git commit -m "migrate: Aman 2.6 autonomous threat intelligence" && git push'
