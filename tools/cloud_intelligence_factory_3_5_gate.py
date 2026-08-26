#!/usr/bin/env python3
from pathlib import Path
import os, subprocess, sys, tempfile, zipfile, json

ROOT=Path(__file__).resolve().parents[1]

def read(rel): return (ROOT/rel).read_text(encoding='utf-8')
def need(cond,label):
    if not cond: raise SystemExit('CLOUD_INTELLIGENCE_FACTORY_3_5_FAILED '+label)

gradle=read('app/build.gradle.kts')
workflow=read('.github/workflows/build.yml')
updater=read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatUpdater.kt')
store=read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatStore.kt')
http=read('app/src/main/java/com/aman/security/autonomous/CloudThreatHttpClient.kt')
pkg=read('app/src/main/java/com/aman/security/autonomous/CloudThreatPackage.kt')
scheduler=read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatScheduler.kt')
builder=read('tools/build_cloud_threat_db.py')
cleanup=read('tools/repository_cleanup_2_6.py')

need('versionName = "1.1.9"' in gradle and 'versionCode = 85' in gradle,'version')
need('AMAN_THREAT_DB_BASE_URL' in gradle,'build_endpoint')
need('schedule:' in workflow and '17 3 * * *' in workflow,'factory_schedule_daily')
need('threat-intelligence:' in workflow and 'build_cloud_threat_db.py' in workflow and 'sign_cloud_threat_db.py' in workflow and 'verify_cloud_threat_db.py' in workflow,'factory_job')
need('AMAN_THREAT_DB_PRIVATE_KEY_B64' in workflow and 'ABUSECH_AUTH_KEY' in workflow and 'PHISHTANK_APP_KEY' in workflow,'factory_secrets')
need('git push --force origin HEAD:aman-threat-db' in workflow,'publish_public_branch')
need("if: github.event_name != 'schedule'" in workflow,'scheduled_intel_without_apk_build')
need('AMAN_THREAT_DB_BASE_URL: https://raw.githubusercontent.com/maen1977/AmanSecurity/aman-threat-db/latest' in workflow,'consumer_endpoint')

# The handset must not contain/provider-contact raw third-party threat-feed hosts.
phone='\n'.join(p.read_text(encoding='utf-8',errors='ignore') for p in (ROOT/'app/src/main/java').rglob('*.kt'))
for host in ['openphish.com','urlhaus.abuse.ch','bazaar.abuse.ch','feodotracker.abuse.ch','api.destroy.tools','threatfox-api.abuse.ch']:
    need(host not in phone,'phone_raw_provider:'+host)
for retired in ['AutonomousThreatHttpClient.kt','AutonomousThreatParsers.kt','AutonomousSourcePolicy.kt']:
    need(not (ROOT/'app/src/main/java/com/aman/security/autonomous'/retired).exists(),'retired_phone_parser:'+retired)

need('CloudThreatSignatureVerifier.verify' in updater and 'manifest.serial < installedSerial' in updater,'signature_and_rollback')
need('TOTAL_SOURCES = 1' in updater and 'ZipInputStream' in updater and 'Unexpected cloud threat package entry' in updater,'single_bounded_package')
need('MappedByteBuffer' in store and 'FileChannel.MapMode.READ_ONLY' in store and 'cloud-intel-v1' in store,'low_heap_mmap_indexes')
need('previous' in store and 'renameTo(currentDirectory)' in store and 'recordCloudFailure' in store,'last_known_good_atomic_swap')
need('raw.githubusercontent.com' in http and 'parts[1] == "AmanSecurity"' in http and 'parts[2] == "aman-threat-db"' in http and 'parts[3] == "latest"' in http,'narrow_endpoint_allowlist')
need('instanceFollowRedirects = false' in http and 'MAX_BUNDLE_BYTES' in pkg and 'SHA256withRSA' in pkg,'transport_package_bounds')
need('PeriodicWorkRequestBuilder<AutonomousThreatWorker>(24, TimeUnit.HOURS, 120, TimeUnit.MINUTES)' in scheduler and 'setInitialDelay' in scheduler and 'NetworkType.CONNECTED' in scheduler and 'setRequiresBatteryNotLow(true)' in scheduler and 'setRequiresStorageNotLow(true)' in scheduler,'daily_distributed_periodic_policy')
need('NetworkType.CONNECTED' in scheduler,'manual_connected_update')
need(('normalized_hashes_and_rules_only_no_raw_malicious_urls' in builder or 'hashes_only_no_raw_malicious_urls' in builder) and 'No malware binaries are downloaded' in builder and 'phishtank_verified_online_urls' in builder and 'decompress_bz2_limited' in builder,'factory_privacy')
need('keys' not in cleanup.split('obsolete_dirs =',1)[1].split(']',1)[0] if 'obsolete_dirs =' in cleanup else True,'public_key_cleanup')

pub=ROOT/'app/src/main/assets/keys/aman-threat-db-public.pem'
need(pub.is_file() and 'BEGIN PUBLIC KEY' in pub.read_text(),'public_verification_key')
# No private signing material may ship in the repository.
private_hits=[]
for p in ROOT.rglob('*'):
    if not p.is_file() or p.stat().st_size>2_000_000: continue
    if any(x in p.parts for x in ('.git','build','dist','__pycache__')) or p.name == 'cloud_intelligence_factory_3_5_gate.py': continue
    try: text=p.read_text(errors='ignore')
    except Exception: continue
    marker='BEGIN ' + 'PRIVATE KEY'; rsa_marker='BEGIN RSA ' + 'PRIVATE KEY'
    if marker in text or rsa_marker in text: private_hits.append(str(p.relative_to(ROOT)))
need(not private_hits,'private_key_in_repo:'+','.join(private_hits))

with tempfile.TemporaryDirectory(prefix='aman-cloud-gate-') as td:
    out=Path(td)/'intel'
    subprocess.run([sys.executable,str(ROOT/'tools/build_cloud_threat_db.py'),'--offline-fixture','--output',str(out),'--min-app-version-code','32'],check=True,stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable,str(ROOT/'tools/prepare_cloud_bundle.py'),'--dir',str(out),'--bundle-name','aman-threat-db-999.zip'],check=True,stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable,str(ROOT/'tools/verify_cloud_threat_db.py'),'--dir',str(out)],check=True,stdout=subprocess.DEVNULL)
    with zipfile.ZipFile(out/'aman-threat-db-999.zip') as z:
        names=set(z.namelist())
        need(names=={'malware_files.sha256','phishing_primary.sha256','phishing_openphish.sha256','phishing_community.sha256','malware_url_hosts.sha256','c2_hosts.sha256','android_cves.txt','apk_indicators.csv','detection_rules.csv'},'fixture_exact_entries')
        joined=b'\n'.join(z.read(n) for n in names)
        need(b'https://' not in joined and b'http://' not in joined,'raw_url_leak_in_mobile_bundle')

print('CLOUD_INTELLIGENCE_FACTORY_3_6_4_OK cloud_factory=1 signed_manifest=1 rollback_guard=1 phone_raw_feeds=0 mmap_indexes=1 apk_identity=1 detection_rules=1 periodic_connected_daily_24h=1 manual_connected=1 last_known_good=1 phishtank_optional=1 raw_urls_in_bundle=0')
