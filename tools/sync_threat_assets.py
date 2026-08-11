#!/usr/bin/env python3
from pathlib import Path
import shutil
ROOT=Path(__file__).resolve().parents[1]
src=ROOT/'threat-db'; dst=ROOT/'app/src/main/assets/threat-db'
dst.mkdir(parents=True, exist_ok=True)
for name in ('manifest.json','signatures.csv','url_indicators.csv','apk_indicators.csv','detection_rules.csv'):
    shutil.copy2(src/name,dst/name)
print('THREAT_ASSET_SYNC_OK files=6')
