#!/usr/bin/env python3
"""Remove legacy GitHub-Actions threat-update files from an upgraded repo.

Run from the Aman repository root:
  python3 tools/repository_cleanup_2_6.py          # preview only
  python3 tools/repository_cleanup_2_6.py --apply  # delete stale legacy files

This does not touch application source, threat-db seed files, or Android data.
"""
from pathlib import Path
import shutil, sys

ROOT = Path(__file__).resolve().parents[1]
APPLY = '--apply' in sys.argv[1:]

LEGACY_PATHS = [
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
    'tools/sign_threat_db.py',
]


def remove(path: Path):
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def main():
    existing = [ROOT / rel for rel in LEGACY_PATHS if (ROOT / rel).exists()]
    if not existing:
        print('REPOSITORY_CLEANUP_2_6_OK stale_paths=0 apply=' + ('1' if APPLY else '0'))
        return

    for path in existing:
        rel = path.relative_to(ROOT)
        print(('DELETE ' if APPLY else 'WOULD_DELETE ') + str(rel))
        if APPLY:
            remove(path)

    print(f'REPOSITORY_CLEANUP_2_6_OK stale_paths={len(existing)} apply={1 if APPLY else 0}')


if __name__ == '__main__':
    main()
