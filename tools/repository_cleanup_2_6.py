#!/usr/bin/env python3
"""Remove legacy threat-update GitHub Actions while preserving the manual build workflow."""
from pathlib import Path
import shutil, sys

ROOT = Path(__file__).resolve().parents[1]
APPLY = '--apply' in sys.argv[1:]

LEGACY_PATHS = [
    'reputation',
    'app/src/main/assets/keys',
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
    if path.is_dir(): shutil.rmtree(path)
    elif path.exists(): path.unlink()

def main():
    stale=[]
    wf_dir=ROOT/'.github/workflows'
    if wf_dir.exists():
        for p in wf_dir.iterdir():
            if p.is_file() and p.name != 'build.yml' and p.suffix.lower() in {'.yml','.yaml'}:
                stale.append(p)
    stale += [ROOT/rel for rel in LEGACY_PATHS if (ROOT/rel).exists()]
    for path in stale:
        rel=path.relative_to(ROOT)
        print(('DELETE ' if APPLY else 'WOULD_DELETE ')+str(rel))
        if APPLY: remove(path)
    print(f'REPOSITORY_CLEANUP_2_6_OK stale_paths={len(stale)} apply={1 if APPLY else 0} build_workflow_preserved=1')

if __name__=='__main__': main()
