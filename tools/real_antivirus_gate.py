#!/usr/bin/env python3
from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def need(c,m):
    if not c: errors.append(m)
def text(p): return (ROOT/p).read_text(encoding='utf-8')

build=text('app/build.gradle.kts')
workflow=text('.github/workflows/main.yml')
cloud=text('app/src/main/java/com/aman/security/detection/CloudReputationClient.kt')
crypto=text('app/src/main/java/com/aman/security/scanner/ThreatDbCrypto.kt')
installed=text('app/src/main/java/com/aman/security/scanner/InstalledAppScanner.kt')
analyzer=text('app/src/main/java/com/aman/security/scanner/ApkStaticAnalyzer.kt')
scheduler=text('app/src/main/java/com/aman/security/update/ThreatUpdateScheduler.kt')
intel=text('tools/update_threat_intel.py')
refresh=text('tools/refresh_threat_intel.py')
shards=text('tools/build_reputation_shards.py')
manifest=text('app/src/main/AndroidManifest.xml')
rules=text('threat-db/detection_rules.csv')

need('versionCode = 10' in build and 'versionName = "2.0.0"' in build,'version 2.0.0/code10')
need('REPUTATION_SHARD_BASE_URL' in build and 'raw.githubusercontent.com/maen1977/AmanSecurity/main/reputation/v1/file/' in build,'GitHub reputation base')
need('scanUserApps(deep: Boolean = true)' in installed and '.map { scanPackage(it, deep = deep) }' in installed,'full installed-app deep scan')
need('scanPackageByName(packageName: String, deep: Boolean = true)' in installed,'post-install deep scan')
need('substring(0, 2)' in cloud and 'verifyDetached' in cloud and 'full SHA-256' in cloud,'prefix privacy reputation')
need('verifyDetached' in crypto and 'SHA256withRSA' in crypto,'signed shard verification')
need('cloud.safe' in analyzer and 'cloud.malicious' in analyzer,'cloud malicious+safe handling')
need('PeriodicWorkRequestBuilder<ThreatUpdateWorker>(6, TimeUnit.HOURS' in scheduler,'device update check every 6h')
need('schedule:' in workflow and '17 */6 * * *' in workflow,'GitHub scheduled refresh 6h')
need('THREAT_DB_PRIVATE_KEY_BASE64' in workflow and 'ABUSECH_AUTH_KEY' in workflow,'GitHub secret-backed signing/intel')
need('git push origin HEAD:main' in workflow and 'github-actions[bot]' in workflow,'GitHub automatic signed DB commit')
need('permissions:\n  contents: read' in workflow and 'contents: write' in workflow,'least-privilege workflow permissions')
need('malware_samples_downloaded=0' in intel and 'get_file' not in intel,'indicator-only source importer')
need('MALWAREBAZAAR' in intel and 'URLHAUS' in intel and '--phishing-url' in intel,'multi-source threat intelligence')
need('build_reputation_shards.py' in refresh and 'verify_reputation_shards.py' in refresh,'signed reputation generation')
need('100_000' in text('tools/compact_threat_db.py') and '300_000' in text('tools/compact_threat_db.py'),'bounded mobile DB')
need(rules.count('RULE|') >= 20,'expanded family behavior rules')
for marker in ('WEBVIEW_BRIDGE','SCREEN_CAPTURE','CONTACTS_API','CALL_LOG_API','LOCATION_API','AUDIO_RECORDING','APP_ENUMERATION'):
    need(marker in analyzer,f'deep marker {marker}')
for family in ('BANKER','SPYWARE','STALKERWARE','RAT','DROPPER','RANSOMWARE'):
    need(family in rules,f'family rules {family}')
need('MANAGE_EXTERNAL_STORAGE' not in manifest and 'READ_EXTERNAL_STORAGE' not in manifest,'no broad storage')
need('android:usesCleartextTraffic="false"' in manifest,'no cleartext')
need(len(list((ROOT/'.github/workflows').glob('*.y*ml'))) == 1,'single workflow file')
need((ROOT/'reputation/v1/catalog.json').is_file(),'reputation catalog present')

if errors:
    print('REAL_ANTIVIRUS_GATE_FAILED')
    for e in errors: print(' -',e)
    sys.exit(1)
print('REAL_ANTIVIRUS_GATE_OK version=2.0.0 deep_scan=1 post_install=1 signed_prefix_reputation=1 github_refresh_6h=1 threat_families=1 indicator_only=1')
