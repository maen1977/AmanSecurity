#!/usr/bin/env python3
"""Bound indicator databases for mobile delivery while preserving reviewed/test entries."""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'threat-db'


def split(path):
    comments=[]; rows=[]
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.lstrip().startswith('#'): comments.append(line)
        else: rows.append(line.strip())
    return comments, rows


def write(path, comments, rows):
    path.write_text('\n'.join(comments + rows).rstrip()+'\n', encoding='utf-8')


def unique_latest(rows, key, cap, preserve=lambda r: False):
    # New imports are appended, so retain the newest indicator for each key.
    seen=set(); out=[]
    for row in reversed(rows):
        k=key(row)
        if k in seen: continue
        seen.add(k); out.append(row)
    out.reverse()
    fixed=[r for r in out if preserve(r)]
    normal=[r for r in out if not preserve(r)]
    if len(normal)>cap: normal=normal[-cap:]
    return fixed+normal


def main():
    fc, fr=split(DB/'signatures.csv')
    fr=unique_latest(fr, lambda r:r.split('|')[0], 100_000, lambda r:r.endswith('|TEST_SIGNATURE'))
    write(DB/'signatures.csv',fc,fr)

    uc, ur=split(DB/'url_indicators.csv')
    ur=unique_latest(ur, lambda r:'|'.join(r.split('|')[:2]), 300_000, lambda r:r.endswith('|TEST_SIGNATURE'))
    write(DB/'url_indicators.csv',uc,ur)

    ac, ar=split(DB/'apk_indicators.csv')
    ar=unique_latest(ar, lambda r:'|'.join(r.split('|')[:2]), 100_000, lambda r:r.endswith('|TEST_SIGNATURE'))
    write(DB/'apk_indicators.csv',ac,ar)

    # Keep structural rules/models/brands and reviewed reputation. Keep metadata only for active IDs.
    dc, dr=split(DB/'detection_rules.csv')
    active=set()
    for r in fr:
        p=r.split('|'); active.add(p[1])
    for r in ur:
        p=r.split('|'); active.add(p[2])
    for r in ar:
        p=r.split('|'); active.add(p[2])
    for r in dr:
        p=r.split('|')
        if p[0]=='REPUTATION' and len(p)==7: active.add(p[3])
    structural=[r for r in dr if not r.startswith('META|')]
    metadata=[]; seen_meta=set()
    for r in reversed(dr):
        p=r.split('|')
        if len(p)==7 and p[0]=='META' and p[1] in active and p[1] not in seen_meta:
            seen_meta.add(p[1]); metadata.append(r)
    metadata.reverse()
    write(DB/'detection_rules.csv',dc,structural+metadata)
    print(f"COMPACT_DB_OK files={len(fr)} urls={len(ur)} apk={len(ar)} detection={len(structural)+len(metadata)}")

if __name__=='__main__': main()
