#!/usr/bin/env python3
"""Validate curated SAFE/MALICIOUS reputation before signing.

SAFE allowlisting is intentionally stricter than malicious reputation because a
false SAFE result can suppress heuristic warnings. SAFE rows therefore require
CONFIRMED confidence and a named review source in threat-intel/reviewed_reputation.csv.
"""
from pathlib import Path
import csv, re, sys

ROOT=Path(__file__).resolve().parents[1]
REVIEWED=ROOT/'threat-intel/reviewed_reputation.csv'
SIG=ROOT/'threat-db/signatures.csv'
HASH_RE=re.compile(r'^[0-9a-f]{64}$')

malicious={}
for line in SIG.read_text(encoding='utf-8').splitlines():
    line=line.strip()
    if not line or line.startswith('#'): continue
    p=line.split('|')
    if len(p)==3 and p[2]=='KNOWN_THREAT': malicious[p[0]]=p[1]

errors=[]; safe=mal=tests=0; seen=set()
if REVIEWED.exists():
    with REVIEWED.open(newline='',encoding='utf-8') as f:
        for row in csv.DictReader(line for line in f if not line.lstrip().startswith('#')):
            if not any(str(v or '').strip() for v in row.values()): continue
            digest=str(row.get('sha256') or '').strip().lower()
            kind=str(row.get('kind') or '').strip().upper()
            disp=str(row.get('disposition') or '').strip().upper()
            conf=str(row.get('confidence') or '').strip().upper()
            src=str(row.get('source') or '').strip().upper()
            rid=str(row.get('id') or '').strip().upper()
            if kind not in {'FILE','SIGNER','PACKAGE','HOST'}: errors.append(f'bad kind {rid}')
            if not HASH_RE.fullmatch(digest): errors.append(f'bad sha256 {rid}')
            key=(kind,digest)
            if key in seen: errors.append(f'duplicate reviewed reputation {kind}:{digest}')
            seen.add(key)
            if disp=='SAFE':
                safe+=1
                if conf!='CONFIRMED': errors.append(f'SAFE must be CONFIRMED {rid}')
                if src in {'','REVIEWED','UNKNOWN','MANUAL'}: errors.append(f'SAFE requires named review source {rid}')
                if kind=='FILE' and digest in malicious: errors.append(f'SAFE conflicts with KNOWN_THREAT {rid}/{malicious[digest]}')
            elif disp=='MALICIOUS': mal+=1
            elif disp=='TEST': tests+=1
            else: errors.append(f'bad disposition {rid}')

if errors:
    print('REVIEWED_REPUTATION_GATE_FAILED')
    for e in errors: print(' -',e)
    sys.exit(1)
print(f'REVIEWED_REPUTATION_GATE_OK safe={safe} malicious={mal} test={tests} safe_requires_confirmed=1')
