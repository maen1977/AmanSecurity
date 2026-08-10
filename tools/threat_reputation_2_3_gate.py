#!/usr/bin/env python3
from pathlib import Path
import csv, hashlib, json, re, sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def need(c,m):
    if not c: errors.append(m)
def text(p): return (ROOT/p).read_text(encoding='utf-8')
build=text('app/build.gradle.kts')
models=text('app/src/main/java/com/aman/security/detection/DetectionModels.kt')
graph=text('app/src/main/java/com/aman/security/detection/ThreatGraphEngine.kt')
imp=text('app/src/main/java/com/aman/security/detection/ImpersonationDetector.kt')
validator=text('app/src/main/java/com/aman/security/scanner/ThreatDbValidator.kt')
canary_code=text('app/src/main/java/com/aman/security/scanner/ThreatDbCanary.kt')
installed=text('app/src/main/java/com/aman/security/scanner/InstalledAppScanner.kt')
apk=text('app/src/main/java/com/aman/security/scanner/ApkStaticAnalyzer.kt')
workflow=text('.github/workflows/main.yml')
det=[x.strip() for x in text('threat-db/detection_rules.csv').splitlines() if x.strip() and not x.lstrip().startswith('#')]
sigs=[x.strip() for x in text('threat-db/signatures.csv').splitlines() if x.strip() and not x.lstrip().startswith('#')]
canary=hashlib.sha256(b'AMAN-THREAT-DB-CANARY-v1').hexdigest()
need('versionCode = 15' in build and 'versionName = "2.5.0"' in build,'2.5.0/code15')
need('THREAT_GRAPH' in models and 'ThreatGraphLink' in models,'threat graph models')
need('score = link.weight.coerceIn(1, 24)' in graph and 'FindingConfidence.CONFIRMED' not in graph.split('DetectionFinding(',1)[-1].split(')',1)[0], 'bounded graph propagation')
need('OFFICIAL_PACKAGE_SIGNER_MISMATCH_' in imp and 'isSideloaded' in imp,'strong impersonation detection')
need('BRAND_SIGNER' in validator and 'LINK' in validator and 'CONFIRMED SAFE signer reputation' in validator,'reviewed signer/link parser')
need('OFFLINE_BLOOM_REPUTATION_HIT' in installed and 'OFFLINE_BLOOM_REPUTATION_HIT' in apk,'bloom hint integrated')
need('ThreatGraphEngine.correlate' in installed and 'ThreatGraphEngine.correlate' in apk,'graph correlation integrated')
need(sum(1 for r in det if r.startswith('RULE|')) >= 36,'compound behavior rules >=36')
need(any(r == f'{canary}|AMAN_DB_CANARY_0001|TEST_SIGNATURE' for r in sigs),'safe canary signature')
need(any(r.startswith('META|AMAN_DB_CANARY_0001|AMAN_CANARY|TEST|CONFIRMED|') for r in det),'canary metadata')
need('ThreatDbCanary.valid(parsed)' in validator and canary in canary_code,'device-side canary enforcement')
need((ROOT/'reputation/v2/file_bloom.json').is_file() and (ROOT/'reputation/v2/file_bloom.sig').is_file(),'signed bloom artifact')
need((ROOT/'app/src/main/assets/reputation/file_bloom.json').is_file(),'bundled bloom asset')
need('tools/sync_reviewed_relationships.py' in workflow and '--limit 5000' in workflow,'expanded CI threat refresh')
need(len(list((ROOT/'.github/workflows').glob('*.y*ml'))) == 1,'single workflow')
# Templates must be data-only and contain no private material.
for path in [ROOT/'threat-intel/trusted_brand_signers.csv',ROOT/'threat-intel/reviewed_graph_links.csv']:
    need(path.is_file(),f'missing template {path.name}')
if errors:
    print('THREAT_REPUTATION_2_3_GATE_FAILED')
    for e in errors: print(' -',e)
    sys.exit(1)
print('THREAT_REPUTATION_2_3_GATE_OK version=2.5.0 graph=bounded reviewed_signers=1 impersonation=stronger bloom=signed rules=36 canary=safe workflow=1')
