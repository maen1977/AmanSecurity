#!/usr/bin/env python3
"""Synchronize reviewed brand signers and threat-graph relationships.

No network access and no malware samples. The generated BRAND_SIGNER/LINK rows
are part of the signed detection database.
"""
from pathlib import Path
import csv, re, sys
ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'threat-db/detection_rules.csv'
SIGNERS=ROOT/'threat-intel/trusted_brand_signers.csv'
LINKS=ROOT/'threat-intel/reviewed_graph_links.csv'
HASH=re.compile(r'^[0-9a-f]{64}$')
ID=re.compile(r'^[A-Z0-9_]{3,96}$')
REL={'SAME_SIGNER','SAME_PACKAGE','SAME_CAMPAIGN','CONTACTS_HOST','DROPS_PAYLOAD','REVIEWED_ASSOCIATION'}
CONF={'LOW','MEDIUM','HIGH','CONFIRMED'}

def read_data():
    raw=DB.read_text(encoding='utf-8').splitlines()
    comments=[x for x in raw if not x.strip() or x.lstrip().startswith('#')]
    rows=[x.strip() for x in raw if x.strip() and not x.lstrip().startswith('#') and not x.startswith(('BRAND_SIGNER|','LINK|'))]
    return comments,rows

def csv_rows(path):
    if not path.exists(): return []
    with path.open(newline='',encoding='utf-8') as f:
        return [r for r in csv.DictReader(line for line in f if not line.lstrip().startswith('#')) if any(str(v or '').strip() for v in r.values())]

def main():
    comments,rows=read_data(); errors=[]
    brands={r.split('|')[1] for r in rows if r.startswith('BRAND|')}
    reps={}
    ids=set()
    for r in rows:
        p=r.split('|')
        if p[0] in {'RULE','BRAND','META'} and len(p)>1: ids.add(p[1])
        if p[0]=='REPUTATION' and len(p)==7:
            reps[(p[1],p[2])]=(p[3],p[4],p[5],p[6]); ids.add(p[3])
    signer_rows=[]
    for r in csv_rows(SIGNERS):
        brand=str(r.get('brand_id') or '').strip().upper(); digest=str(r.get('sha256') or '').strip().lower(); source=str(r.get('source') or '').strip(); reviewed=str(r.get('reviewed_at') or '').strip()
        if brand not in brands: errors.append(f'unknown brand {brand}'); continue
        if not HASH.fullmatch(digest): errors.append(f'bad signer hash {brand}'); continue
        rep=reps.get(('SIGNER',digest))
        if not rep or rep[2] != 'CONFIRMED' or rep[3] != 'SAFE': errors.append(f'brand signer must have CONFIRMED SAFE SIGNER reputation {brand}'); continue
        if not source or not reviewed: errors.append(f'brand signer missing source/review date {brand}'); continue
        signer_rows.append(f'BRAND_SIGNER|{brand}|{digest}')
    link_rows=[]
    seen=set()
    for r in csv_rows(LINKS):
        a=str(r.get('from_id') or '').strip().upper(); b=str(r.get('to_id') or '').strip().upper(); rel=str(r.get('relation') or '').strip().upper(); conf=str(r.get('confidence') or '').strip().upper(); source=str(r.get('source') or '').strip(); reviewed=str(r.get('reviewed_at') or '').strip()
        try: weight=int(str(r.get('weight') or '').strip())
        except Exception: weight=-1
        if not ID.fullmatch(a) or not ID.fullmatch(b) or a==b: errors.append(f'bad graph ids {a}/{b}'); continue
        if a not in ids or b not in ids: errors.append(f'graph ids must reference known records {a}/{b}'); continue
        if rel not in REL or conf not in CONF or not (1<=weight<=24): errors.append(f'bad graph relationship {a}/{b}'); continue
        if not source or not reviewed: errors.append(f'graph link missing source/review date {a}/{b}'); continue
        key=(a,b,rel)
        if key in seen: errors.append(f'duplicate graph link {a}/{b}/{rel}'); continue
        seen.add(key); link_rows.append(f'LINK|{a}|{b}|{rel}|{conf}|{weight}')
    if errors:
        print('REVIEWED_RELATIONSHIPS_GATE_FAILED')
        for e in errors: print(' -',e)
        sys.exit(1)
    # Keep rows grouped: rules, brands, brand signers, model/reputation/meta, graph links.
    out=[]; inserted_signers=False
    for row in rows:
        if not inserted_signers and not row.startswith(('RULE|','BRAND|')):
            out.extend(sorted(set(signer_rows))); inserted_signers=True
        out.append(row)
    if not inserted_signers: out.extend(sorted(set(signer_rows)))
    out.extend(sorted(set(link_rows)))
    DB.write_text('\n'.join(comments+out).rstrip()+'\n',encoding='utf-8')
    print(f'REVIEWED_RELATIONSHIPS_OK brand_signers={len(set(signer_rows))} graph_links={len(set(link_rows))}')
if __name__=='__main__': main()
