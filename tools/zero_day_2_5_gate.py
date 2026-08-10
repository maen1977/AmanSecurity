#!/usr/bin/env python3
from pathlib import Path
import json, re, sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def need(cond,msg):
    if not cond: errors.append(msg)
def text(path): return (ROOT/path).read_text(encoding='utf-8')

build=text('app/build.gradle.kts')
models=text('app/src/main/java/com/aman/security/detection/DetectionModels.kt')
engine=text('app/src/main/java/com/aman/security/detection/ZeroDayHeuristicEngine.kt')
analyzer=text('app/src/main/java/com/aman/security/scanner/ApkStaticAnalyzer.kt')
verdict=text('app/src/main/java/com/aman/security/detection/VerdictEngine.kt')
rules=[x.strip() for x in text('threat-db/detection_rules.csv').splitlines() if x.strip() and not x.lstrip().startswith('#')]
manifest=json.loads(text('threat-db/manifest.json'))
workflow=list((ROOT/'.github/workflows').glob('*.y*ml'))

need('versionCode = 15' in build and 'versionName = "2.5.0"' in build,'version 2.5.0/code15')
need('ZERO_DAY_HEURISTIC' in models and 'ZeroDayProfile' in models,'zero-day models')
need('ZERO_DAY_HIDDEN_DEX_LOADER' in engine and 'ZERO_DAY_STEALTH_ANTI_ANALYSIS' in engine,'zero-day capability chains')
need('HIDDEN_DEX_PAYLOAD' in analyzer and 'HIDDEN_ELF_PAYLOAD' in analyzer,'hidden executable payload inspection')
need('HIGH_ENTROPY_ASSET' in analyzer and 'shannonEntropy' in analyzer,'bounded entropy inspection')
need('ANTI_DEBUG' in analyzer and 'EMULATOR_CHECK' in analyzer,'anti-analysis markers')
need('MAX_ASSET_SAMPLE_TOTAL_BYTES' in analyzer and 'MAX_ASSET_CANDIDATES' in analyzer,'bounded asset scanning')
need('EvidenceDomain' in verdict and 'ZERO_DAY_HEURISTIC' in verdict,'correlated evidence-domain scoring')
need(sum(1 for r in rules if r.startswith('RULE|')) >= 36,'behavior/signature rules >=36')
need(any(r.startswith('MODEL|HIDDEN_PAYLOAD|') for r in rules),'hidden payload model feature')
need(any(r.startswith('MODEL|ANTI_ANALYSIS|') for r in rules),'anti-analysis model feature')
need(int(manifest.get('detectionEntries',0)) >= 83,'signed detection entries >=83')
need(len(workflow)==1,'single workflow')
need('zero_day_2_5_gate.py' in workflow[0].read_text(encoding='utf-8') if workflow else False,'workflow zero-day gate')
if errors:
    print('ZERO_DAY_2_5_GATE_FAILED')
    for e in errors: print(' - '+e)
    sys.exit(1)
print('ZERO_DAY_2_5_GATE_OK version=2.5.0 hidden_payloads=1 anti_analysis=1 evidence_domains=1 rules>=36 bounded_scan=1 workflow=1')
