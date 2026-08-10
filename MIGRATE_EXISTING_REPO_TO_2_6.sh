#!/usr/bin/env bash
set -euo pipefail
[[ -d .git ]] || { echo 'ERROR: Run from repo root.' >&2; exit 1; }
python3 tools/repository_cleanup_2_6.py --apply
git add -A
python3 tools/quality_gate.py
[[ -f .github/workflows/build.yml ]] || { echo 'ERROR: build.yml missing.' >&2; exit 1; }
echo 'MIGRATION_2_7_READY: legacy threat-update Actions removed; automatic build workflow preserved.'
