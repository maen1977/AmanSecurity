#!/usr/bin/env python3
"""Continuity gate for Aman 2.6 autonomous local seed data.

This intentionally does not depend on the retired signed-reputation/GitHub
pipeline. It protects only the static seed that ships with the APK. Runtime
feeds are validated by the Android autonomous updater and its per-source store.
"""
from pathlib import Path
import json, sys

ROOT = Path(__file__).resolve().parents[1]
CONF = json.loads((ROOT / 'threat-intel/minimum_coverage.json').read_text(encoding='utf-8'))


def records(path: Path):
    return [
        line.strip() for line in path.read_text(encoding='utf-8').splitlines()
        if line.strip() and not line.lstrip().startswith('#')
    ]


def main():
    signatures = records(ROOT / 'threat-db/signatures.csv')
    known = sum(1 for line in signatures if line.endswith('|KNOWN_THREAT'))
    detection = records(ROOT / 'threat-db/detection_rules.csv')
    rules = [line for line in detection if line.startswith('RULE|')]
    rule_families = {
        parts[2]
        for line in rules
        if len((parts := line.split('|'))) > 2
    }

    errors = []
    if known < int(CONF['minimumKnownThreatFileHashes']):
        errors.append(f'known_threat_hashes={known}')
    if len(detection) < int(CONF['minimumDetectionRecords']):
        errors.append(f'detection_records={len(detection)}')
    if len(rules) < int(CONF['minimumBehaviorRules']):
        errors.append(f'behavior_rules={len(rules)}')
    missing = sorted(set(CONF['requiredRuleFamilies']) - rule_families)
    if missing:
        errors.append('missing_rule_families=' + ','.join(missing))

    if errors:
        print('AUTONOMOUS_CONTINUITY_GATE_FAILED')
        for error in errors:
            print(' - ' + error)
        sys.exit(1)

    print(
        'AUTONOMOUS_CONTINUITY_GATE_OK '
        f'known_threat_hashes={known} detection_records={len(detection)} '
        f'behavior_rules={len(rules)} required_families={len(CONF["requiredRuleFamilies"])} '
        'signed_reputation_dependency=0'
    )


if __name__ == '__main__':
    main()
