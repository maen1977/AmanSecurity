#!/usr/bin/env python3
"""GitHub Actions threat-intelligence refresh orchestrator.

Downloads indicators/metadata only. It never requests malware sample binaries.
When source data changes, it compacts, increments the serial, signs the database,
syncs Android assets, and rebuilds signed prefix reputation shards.
"""
from pathlib import Path
import argparse, datetime as dt, hashlib, json, os, subprocess, sys

ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'threat-db'
TRACKED=('signatures.csv','url_indicators.csv','apk_indicators.csv','detection_rules.csv')


def fingerprint():
    h=hashlib.sha256()
    for name in TRACKED: h.update((DB/name).read_bytes())
    return h.hexdigest()


def run(*args, env=None):
    subprocess.run([sys.executable,*map(str,args)],cwd=ROOT,env=env,check=True)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--private-key', required=True)
    ap.add_argument('--limit', type=int, default=1000)
    ap.add_argument('--force-sign', action='store_true')
    args=ap.parse_args()
    key=Path(args.private_key).expanduser().resolve()
    if not key.is_file(): raise SystemExit('Private key not found')
    if ROOT in key.parents: raise SystemExit('Private key must stay outside project')

    before=fingerprint(); used=[]
    env=os.environ.copy()
    abuse=env.get('ABUSECH_AUTH_KEY','').strip()
    if abuse:
        run('tools/update_threat_intel.py','--malwarebazaar','--urlhaus','--limit',str(args.limit),env=env); used += ['MALWAREBAZAAR','URLHAUS']
    else:
        print('THREAT_SOURCE_SKIPPED source=abuse.ch reason=missing_ABUSECH_AUTH_KEY')
    phishing=env.get('PHISHING_FEED_URL','').strip()
    if phishing:
        run('tools/update_threat_intel.py','--phishing-url',phishing,'--limit',str(args.limit),env=env); used.append('PHISHING_FEED')
    reviewed=ROOT/'threat-intel/reviewed_reputation.csv'
    if reviewed.is_file() and sum(1 for line in reviewed.read_text(encoding='utf-8').splitlines() if line.strip() and not line.lstrip().startswith('#'))>1:
        run('tools/update_threat_intel.py','--reputation-file',reviewed,'--limit','100000',env=env); used.append('REVIEWED_REPUTATION')

    run('tools/compact_threat_db.py')
    changed = fingerprint()!=before
    if not changed and not args.force_sign:
        print('THREAT_REFRESH_NO_CHANGE sources='+(','.join(used) if used else 'none'))
        return

    old=json.loads((DB/'manifest.json').read_text(encoding='utf-8'))
    serial=int(old.get('serial',0))+1
    now=dt.datetime.now(dt.timezone.utc)
    version=now.strftime('%Y.%m.%d.%H%M')
    run('tools/sign_threat_db.py','--private-key',key,'--serial',str(serial),'--version',version,'--min-app-version-code','10')
    run('tools/sync_threat_assets.py')
    subprocess.run([sys.executable,'tools/build_reputation_shards.py','--private-key',str(key)],cwd=ROOT,check=True)
    run('tools/verify_threat_db.py')
    run('tools/verify_reputation_shards.py')
    print(f"THREAT_REFRESH_OK serial={serial} version={version} sources={','.join(used) if used else 'none'} malware_binaries_downloaded=0")

if __name__=='__main__': main()
