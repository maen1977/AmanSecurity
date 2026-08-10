#!/usr/bin/env python3
from pathlib import Path
import argparse, datetime as dt, json, sys
ap=argparse.ArgumentParser(); ap.add_argument('status',type=Path); ap.add_argument('--max-age-hours',type=float,default=24); args=ap.parse_args()
if not args.status.exists():
    print('THREAT_SOURCE_HEALTH_GATE_OK status=absent refresh_not_run=1'); raise SystemExit(0)
data=json.loads(args.status.read_text(encoding='utf-8'))
try: generated=dt.datetime.fromisoformat(data['generatedAt'].replace('Z','+00:00'))
except Exception: print('THREAT_SOURCE_HEALTH_GATE_FAILED invalid_generatedAt'); raise SystemExit(1)
age=(dt.datetime.now(dt.timezone.utc)-generated).total_seconds()/3600
if age > args.max_age_hours:
    print(f'THREAT_SOURCE_HEALTH_GATE_FAILED stale_status_hours={age:.1f}'); raise SystemExit(1)
sources=data.get('sources') or {}; enabled=[(k,v) for k,v in sources.items() if v.get('enabled')]
failed=[k for k,v in enabled if not v.get('ok')]
succeeded=[k for k,v in enabled if v.get('ok')]
# A feed outage should not block an otherwise valid release; the last signed DB remains active.
# However, a refresh that claims enabled sources with zero successes is surfaced distinctly.
state='healthy' if not failed else ('degraded' if succeeded else 'offline')
print(f'THREAT_SOURCE_HEALTH_GATE_OK state={state} enabled={len(enabled)} succeeded={len(succeeded)} failed={len(failed)} last_signed_db_preserved=1')
if failed: print('THREAT_SOURCE_WARN failed='+','.join(failed))
