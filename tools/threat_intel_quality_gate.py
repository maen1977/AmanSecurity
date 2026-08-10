#!/usr/bin/env python3
"""Cross-file threat-intelligence consistency gate."""
from pathlib import Path
import re, sys
ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'threat-db'

def rows(name):
    return [x.strip() for x in (DB/name).read_text(encoding='utf-8').splitlines() if x.strip() and not x.lstrip().startswith('#')]

sig=rows('signatures.csv'); urls=rows('url_indicators.csv'); det=rows('detection_rules.csv')
metadata={}
reputation=[]
for raw in det:
    p=raw.split('|')
    if p[0]=='META' and len(p)==7: metadata[p[1]]=p
    if p[0]=='REPUTATION' and len(p)==7: reputation.append(p)

errors=[]; known=[]; test=0
for raw in sig:
    p=raw.split('|')
    if len(p)!=3: continue
    if p[2]=='KNOWN_THREAT':
        known.append((p[0],p[1]))
        if p[1] not in metadata: errors.append(f'missing META for signature {p[1]}')
        elif metadata[p[1]][3] in {'UNKNOWN','TEST'}: errors.append(f'bad family for known threat {p[1]}')
    elif p[2]=='TEST_SIGNATURE': test+=1

for raw in urls:
    p=raw.split('|')
    if len(p)!=4: continue
    if p[3] != 'TEST_SIGNATURE' and p[2] not in metadata: errors.append(f'missing META for URL indicator {p[2]}')

mal_hashes={h for h,_ in known}
for p in reputation:
    if p[1]=='FILE' and p[6]=='SAFE' and p[2] in mal_hashes:
        errors.append(f'SAFE reputation conflicts with malicious signature {p[2]}')

rule_count=sum(1 for r in det if r.startswith('RULE|'))
if rule_count < 29: errors.append(f'behavior rule count too low: {rule_count}')
if len(known) < 8: errors.append(f'known mobile threat hashes too low for bundled regression base: {len(known)}')
canary='99690a84a5003e207911b71281aa8aba067ac0378428575dfc2992f26fab0337'
if not any(r.startswith(canary+'|AMAN_DB_CANARY_0001|TEST_SIGNATURE') for r in sig): errors.append('safe threat DB canary missing')
# Project must never contain malware binaries or common encrypted sample archives.
for p in ROOT.rglob('*'):
    if p.is_file() and p.suffix.lower() in {'.apk','.dex','.jar'} and 'build' not in p.parts:
        errors.append(f'binary payload forbidden in repository: {p.relative_to(ROOT)}')
    if p.is_file() and p.name.lower() in {'malware.zip','infected.zip'}:
        errors.append(f'malware archive forbidden: {p.relative_to(ROOT)}')

if errors:
    print('THREAT_INTEL_QUALITY_GATE_FAILED')
    for e in errors: print(' -',e)
    sys.exit(1)
print(f'THREAT_INTEL_QUALITY_GATE_OK known_hashes={len(known)} test_hashes={test} behavior_rules={rule_count} malware_binaries=0 metadata_complete=1')
