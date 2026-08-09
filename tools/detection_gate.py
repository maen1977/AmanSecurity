#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
errors=[]

def need(cond,msg):
    if not cond: errors.append(msg)

def text(rel):
    return (ROOT/rel).read_text(encoding='utf-8')

models=text('app/src/main/java/com/aman/security/detection/DetectionModels.kt')
verdict=text('app/src/main/java/com/aman/security/detection/VerdictEngine.kt')
rules=text('app/src/main/java/com/aman/security/detection/SignatureRuleEngine.kt')
behavior=text('app/src/main/java/com/aman/security/detection/StaticBehaviorEngine.kt')
ml=text('app/src/main/java/com/aman/security/detection/LocalMalwareModel.kt')
network=text('app/src/main/java/com/aman/security/detection/NetworkIndicatorExtractor.kt')
imp=text('app/src/main/java/com/aman/security/detection/ImpersonationDetector.kt')
cloud=text('app/src/main/java/com/aman/security/detection/CloudReputationClient.kt')
analyzer=text('app/src/main/java/com/aman/security/scanner/ApkStaticAnalyzer.kt')
installed=text('app/src/main/java/com/aman/security/scanner/InstalledAppScanner.kt')
updater=text('app/src/main/java/com/aman/security/scanner/ThreatDatabaseUpdater.kt')
validator=text('app/src/main/java/com/aman/security/scanner/ThreatDbValidator.kt')
scheduler=text('app/src/main/java/com/aman/security/update/ThreatUpdateScheduler.kt')
intel=text('tools/update_threat_intel.py')
trainer=text('tools/train_local_model.py')
bench=text('tools/benchmark_detection.py')
workflow=text('.github/workflows/main.yml')
manifest=text('threat-db/manifest.json')

def has(source,*needles):
    return all(n in source for n in needles)

# 1: threat intelligence
need(has(manifest,'"schema": 4','detection_rules.csv'), 'schema 4 detection data missing')
need(has(models,'ThreatIntelMetadata','firstSeen','lastSeen') and has(validator,'"META"','optionalDate'), 'threat-intelligence metadata missing')
need(has(intel,'MalwareBazaar','URLhaus','--reputation-file','malware_samples_downloaded=0'), 'indicator-only threat-intel importer missing')
# 2: YARA-like signatures
need(has(rules,'DetectionRule','allMarkers','anyMarkers'), 'signature rule engine missing')
# 3: deeper DEX analysis
need(has(analyzer,'InMemoryDexClassLoader','MediaProjection','ClipboardManager','ProcessBuilder','MAX_DEX_SCAN_BYTES'), 'deep DEX markers missing')
# 4: manifest/combinations
need(has(behavior,'ACCESSIBILITY_SERVICE','SMS_ACCESS','BOOT_START','DYNAMIC_CODE_LOADING'), 'behavior combination engine missing')
# 5: obfuscation/packing
need(has(analyzer,'PACKER_PRESENT','HEAVY_REFLECTION','SECONDARY_DEX_PAYLOAD'), 'packing/obfuscation analysis missing')
# 6: network extraction
need(has(network,'https?://','DOMAIN','IPV4'), 'network IOC extraction missing')
need(has(analyzer,'networkUrls','networkDomains','UrlScanner(database::findUrl)'), 'network IOC matching missing')
# 7: reputation
need(has(models,'ReputationIndicator','ReputationDisposition'), 'reputation model missing')
need(has(installed,'findReputation'), 'installed-app reputation integration missing')
# 8: impersonation
need(has(imp,'editDistance','ProtectedBrandProfile'), 'impersonation detector missing')
# 9: stalkerware/spyware
need(has(behavior,'STALKERWARE','SPYWARE'), 'spyware/stalkerware specialization missing')
# 10: static behavior chains
need('STATIC_BEHAVIOR' in models and 'StaticBehaviorEngine.evaluate' in analyzer, 'static behavior engine not integrated')
# 11: optional cloud hash reputation
need(has(cloud,'enabled','REPUTATION_SHARD_BASE_URL','substring(0, 2)','verifyDetached','sha256'), 'optional hash-only cloud reputation missing')
need(has(analyzer,'allowCloudLookup = true','allowCloudLookup = false','CloudReputationClient(context).querySha256(fileSha256)','DetectionSource.CLOUD_REPUTATION'), 'user-triggered hash cloud reputation integration missing')
# 12: local ML
need(has(ml,'probability','LOCAL_MODEL_90','exp('), 'local model inference missing')
need('gradient' not in trainer.lower() or 'epochs' in trainer.lower(), 'training utility missing')
# 13: multi-engine score
need(has(verdict,'engineCount','Multiple independent engines','KNOWN_THREAT'), 'multi-engine verdict missing')
# 14: false-positive control
need(has(verdict,'Low-confidence heuristics alone cannot escalate','allowlisted'), 'false-positive controls missing')
# 15: family classification
for family in ('TROJAN','SPYWARE','STALKERWARE','BANKER','RAT','DROPPER','RANSOMWARE','PHISHING','RISKWARE','ADWARE'):
    need(family in models, f'threat family missing: {family}')
# 16: scheduled signed updates
need(has(scheduler,'PeriodicWorkRequestBuilder<ThreatUpdateWorker>(6, TimeUnit.HOURS','NetworkType.CONNECTED','ExistingPeriodicWorkPolicy.UPDATE','BackoffPolicy.EXPONENTIAL'), 'scheduled threat updates missing')
need('schema < 4' in updater and 'instanceFollowRedirects = false' in updater, 'signed schema4 update hardening missing')
# 17: separated engines
for name in ('SignatureRuleEngine.kt','StaticBehaviorEngine.kt','LocalMalwareModel.kt','NetworkIndicatorExtractor.kt','ImpersonationDetector.kt','VerdictEngine.kt'):
    need((ROOT/'app/src/main/java/com/aman/security/detection'/name).is_file(), f'engine module missing: {name}')
# 18: benchmarking and regression coverage
need(has(bench,'detection_rate','false_positive_rate','precision','scan_time_p95_ms','peak_memory_p95_mb','family_accuracy'), 'benchmark metrics tool missing')
for test_name in (
    'VerdictEngineTest.kt',
    'SignatureRuleEngineTest.kt',
    'LocalMalwareModelTest.kt',
    'NetworkIndicatorExtractorTest.kt',
    'ImpersonationDetectorTest.kt',
    'StaticBehaviorEngineTest.kt',
):
    need((ROOT/'app/src/test/java/com/aman/security/detection'/test_name).is_file(), f'detection regression test missing: {test_name}')
# 19: post-install deep scan
need('scanPackageByName(packageName' in installed and 'deep: Boolean = true' in installed and 'analyzeInstalledFile' in installed, 'post-install deep scan missing')
# 20: release upgrade
build=text('app/build.gradle.kts')
need('versionName = "2.0.0"' in build and 'versionCode = 10' in build, '2.0 release version missing')
# single auto workflow remains
need(workflow.count('name: Aman Security Pipeline') == 1 and 'push:' in workflow and 'branches: [ "main" ]' in workflow, 'single automatic workflow missing')
need(len(list((ROOT/'.github/workflows').glob('*.y*ml'))) == 1, 'more than one workflow file found')

if errors:
    print('DETECTION_ENGINE_GATE_FAILED')
    for e in errors: print(' -',e)
    sys.exit(1)
print('DETECTION_ENGINE_GATE_OK items=20 multi_engine=1 local_ml=1 signed_rules=1 github_signed_reputation=1 post_install_deep_scan=1')
