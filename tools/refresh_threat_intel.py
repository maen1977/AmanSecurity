#!/usr/bin/env python3
"""GitHub Actions threat-intelligence refresh orchestrator.

External source outages never destroy the last known-good signed database. Each
source is attempted independently, the source-health report is emitted for CI,
and a new database is signed only when validated indicator content changes.
Malware binaries are never requested or downloaded.
"""
from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / 'threat-db'
STATUS = ROOT / 'threat-intel' / 'source_status.json'
TRACKED = ('signatures.csv', 'url_indicators.csv', 'apk_indicators.csv', 'detection_rules.csv')
ADDED_RE = re.compile(r"added_indicators=(\d+)")


def fingerprint():
    h = hashlib.sha256()
    for name in TRACKED:
        h.update((DB / name).read_bytes())
    return h.hexdigest()


def run_checked(*args, env=None):
    subprocess.run([sys.executable, *map(str, args)], cwd=ROOT, env=env, check=True)


def run_source(name: str, args: list[str], env: dict[str, str]):
    started = dt.datetime.now(dt.timezone.utc)
    proc = subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    combined = (proc.stdout or '') + ('\n' + proc.stderr if proc.stderr else '')
    m = ADDED_RE.search(combined)
    result = {
        'enabled': True,
        'ok': proc.returncode == 0,
        'added': int(m.group(1)) if m else 0,
        'checkedAt': started.replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
    }
    if proc.returncode != 0:
        # Keep the error short; secrets are never echoed by the importer.
        last = [line.strip() for line in combined.splitlines() if line.strip()][-3:]
        result['error'] = ' | '.join(last)[:500]
        print(f"THREAT_SOURCE_FAILED source={name} detail={result['error']}")
    else:
        print(proc.stdout.strip())
        print(f"THREAT_SOURCE_OK source={name} added={result['added']}")
    return result


def write_status(refresh_enabled: bool, source_results: dict, data_changed: bool, signed: bool):
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    payload = {
        'schema': 1,
        'generatedAt': now,
        'refreshEnabled': refresh_enabled,
        'dataChanged': data_changed,
        'signed': signed,
        'malwareBinariesDownloaded': 0,
        'sources': source_results,
    }
    STATUS.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(f"THREAT_SOURCE_STATUS path={STATUS.relative_to(ROOT)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--private-key', required=True)
    ap.add_argument('--limit', type=int, default=5000)
    ap.add_argument('--force-sign', action='store_true')
    args = ap.parse_args()
    key = Path(args.private_key).expanduser().resolve()
    if not key.is_file():
        raise SystemExit('Private key not found')
    if ROOT in key.parents:
        raise SystemExit('Private key must stay outside project')

    before = fingerprint()
    before_bytes = {name: (DB / name).read_bytes() for name in TRACKED}
    env = os.environ.copy()
    source_results = {}
    abuse = env.get('ABUSECH_AUTH_KEY', '').strip()
    phishing = env.get('PHISHING_FEED_URL', '').strip()

    if abuse:
        source_results['MALWAREBAZAAR_ANDROID'] = run_source(
            'MALWAREBAZAAR_ANDROID',
            ['tools/update_threat_intel.py', '--malwarebazaar', '--limit', str(args.limit)],
            env,
        )
        source_results['URLHAUS'] = run_source(
            'URLHAUS',
            ['tools/update_threat_intel.py', '--urlhaus', '--limit', str(args.limit)],
            env,
        )
    else:
        source_results['MALWAREBAZAAR_ANDROID'] = {'enabled': False, 'ok': False, 'added': 0, 'reason': 'missing_ABUSECH_AUTH_KEY'}
        source_results['URLHAUS'] = {'enabled': False, 'ok': False, 'added': 0, 'reason': 'missing_ABUSECH_AUTH_KEY'}
        print('THREAT_SOURCE_SKIPPED source=abuse.ch reason=missing_ABUSECH_AUTH_KEY')

    if phishing:
        source_results['PHISHING_FEED'] = run_source(
            'PHISHING_FEED',
            ['tools/update_threat_intel.py', '--phishing-url', phishing, '--limit', str(args.limit)],
            env,
        )
    else:
        source_results['PHISHING_FEED'] = {'enabled': False, 'ok': False, 'added': 0, 'reason': 'missing_PHISHING_FEED_URL'}

    # Treat one refresh cycle transactionally: if any configured external feed fails,
    # discard changes gathered from the other external feeds and preserve the last
    # complete signed snapshot. A later scheduled run can retry the whole set.
    external = {k: v for k, v in source_results.items() if k != 'REVIEWED_REPUTATION' and v.get('enabled')}
    failed_external = [k for k, v in external.items() if not v.get('ok')]
    if failed_external:
        for name, data in before_bytes.items():
            (DB / name).write_bytes(data)
        print('THREAT_REFRESH_TRANSACTION_ROLLBACK failed_sources=' + ','.join(failed_external) + ' last_signed_db_preserved=1')

    reviewed = ROOT / 'threat-intel/reviewed_reputation.csv'
    if reviewed.is_file() and sum(1 for line in reviewed.read_text(encoding='utf-8').splitlines() if line.strip() and not line.lstrip().startswith('#')) > 1:
        # A malformed local reviewed file is a repository-integrity problem, so fail hard.
        run_checked('tools/update_threat_intel.py', '--reputation-file', reviewed, '--limit', '100000', env=env)
        source_results['REVIEWED_REPUTATION'] = {'enabled': True, 'ok': True, 'added': 0, 'checkedAt': dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')}
    else:
        source_results['REVIEWED_REPUTATION'] = {'enabled': False, 'ok': True, 'added': 0, 'reason': 'no_reviewed_rows'}

    # Local quality checks run before signing; malformed repository data is fatal.
    run_checked('tools/sync_reviewed_relationships.py')
    run_checked('tools/compact_threat_db.py')
    run_checked('tools/reviewed_reputation_gate.py')
    run_checked('tools/threat_intel_quality_gate.py')

    changed = fingerprint() != before
    signed = False
    if changed or args.force_sign:
        old = json.loads((DB / 'manifest.json').read_text(encoding='utf-8'))
        serial = int(old.get('serial', 0)) + 1
        now = dt.datetime.now(dt.timezone.utc)
        version = now.strftime('%Y.%m.%d.%H%M')
        run_checked('tools/sign_threat_db.py', '--private-key', key, '--serial', str(serial), '--version', version, '--min-app-version-code', '15')
        run_checked('tools/sync_threat_assets.py')
        subprocess.run([sys.executable, 'tools/build_reputation_shards.py', '--private-key', str(key)], cwd=ROOT, check=True)
        run_checked('tools/verify_threat_db.py')
        run_checked('tools/verify_reputation_shards.py')
        signed = True
        print(f"THREAT_REFRESH_OK serial={serial} version={version} malware_binaries_downloaded=0")
    else:
        print('THREAT_REFRESH_NO_CHANGE using_last_signed_database=1')

    write_status(True, source_results, changed, signed)


if __name__ == '__main__':
    main()
