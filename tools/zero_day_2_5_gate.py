#!/usr/bin/env python3
from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def need(c,m):
 if not c: errors.append(m)
def text(p): return (ROOT/p).read_text(encoding='utf-8')
build=text('app/build.gradle.kts'); models=text('app/src/main/java/com/aman/security/detection/DetectionModels.kt'); engine=text('app/src/main/java/com/aman/security/detection/ZeroDayHeuristicEngine.kt'); analyzer=text('app/src/main/java/com/aman/security/scanner/ApkStaticAnalyzer.kt'); verdict=text('app/src/main/java/com/aman/security/detection/VerdictEngine.kt')
rules=[x.strip() for x in text('threat-db/detection_rules.csv').splitlines() if x.strip() and not x.lstrip().startswith('#')]
m=json.loads(text('threat-db/manifest.json'))
need('versionCode = 69' in build and 'versionName = "9.0.11"' in build,'version code49/code48')
need('ZERO_DAY_HEURISTIC' in models and 'ZeroDayProfile' in models,'zero-day models')
need('ZERO_DAY_HIDDEN_DEX_LOADER' in engine and 'ZERO_DAY_STEALTH_ANTI_ANALYSIS' in engine,'zero-day chains')
need('HIDDEN_DEX_PAYLOAD' in analyzer and 'HIDDEN_ELF_PAYLOAD' in analyzer,'hidden payload inspection')
need('HIGH_ENTROPY_ASSET' in analyzer and 'shannonEntropy' in analyzer,'entropy inspection')
need('ANTI_DEBUG' in analyzer and 'EMULATOR_CHECK' in analyzer,'anti-analysis markers')
need('EvidenceDomain' in verdict and 'ZERO_DAY_HEURISTIC' in verdict,'evidence-domain scoring')
need(sum(1 for r in rules if r.startswith('RULE|')) >= 36,'rules >=36')
need(int(m.get('detectionEntries',0)) >= 83,'detection entries >=83')
if errors:
 print('ZERO_DAY_2_5_GATE_FAILED'); [print(' - '+e) for e in errors]; sys.exit(1)
print('ZERO_DAY_2_5_GATE_OK retained_in_3_1=1 hidden_payloads=1 anti_analysis=1 evidence_domains=1 rules>=36')
