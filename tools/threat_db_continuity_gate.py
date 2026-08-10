#!/usr/bin/env python3
from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parents[1]
conf=json.loads((ROOT/'threat-intel/minimum_coverage.json').read_text(encoding='utf-8'))

def records(path):
    return [line.strip() for line in path.read_text(encoding='utf-8').splitlines() if line.strip() and not line.lstrip().startswith('#')]

sigs=records(ROOT/'threat-db/signatures.csv')
known=sum(1 for line in sigs if line.endswith('|KNOWN_THREAT'))
detection=records(ROOT/'threat-db/detection_rules.csv')
rule_families={line.split('|')[2] for line in detection if line.startswith('RULE|') and len(line.split('|')) > 2}
rep_catalog=json.loads((ROOT/'reputation/v1/catalog.json').read_text(encoding='utf-8'))
rep_entries=int(rep_catalog.get('totalEntries', rep_catalog.get('entries', 0)))
errors=[]
if known < int(conf['minimumKnownThreatFileHashes']): errors.append(f'known_threat_hashes={known}')
if len(detection) < int(conf['minimumDetectionRecords']): errors.append(f'detection_records={len(detection)}')
if rep_entries < int(conf['minimumSignedReputationEntries']): errors.append(f'reputation_entries={rep_entries}')
missing=sorted(set(conf['requiredRuleFamilies'])-rule_families)
if missing: errors.append('missing_rule_families='+','.join(missing))
if errors:
    print('THREAT_DB_CONTINUITY_GATE_FAILED')
    for e in errors: print(' - '+e)
    sys.exit(1)
print(f'THREAT_DB_CONTINUITY_GATE_OK known_threat_hashes={known} detection_records={len(detection)} reputation_entries={rep_entries} required_families={len(conf["requiredRuleFamilies"])}')
