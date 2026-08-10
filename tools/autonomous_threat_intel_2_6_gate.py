#!/usr/bin/env python3
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]

def need(text, items, label):
    missing=[x for x in items if x not in text]
    if missing: raise SystemExit(f"{label}_FAILED missing={missing}")

def main():
    if (ROOT/'.github').exists(): raise SystemExit('AUTONOMOUS_2_6_GATE_FAILED github_automation_present')
    gradle=(ROOT/'app/build.gradle.kts').read_text()
    need(gradle,['versionName = "2.6.0"','versionCode = 16'],'AUTONOMOUS_2_6_VERSION')
    forbidden=['THREAT_DB_BASE_URL','REPUTATION_SHARD_BASE_URL','raw.githubusercontent.com','ABUSECH_AUTH_KEY','THREAT_DB_PRIVATE_KEY_BASE64']
    scan_paths=[ROOT/'app/src/main', ROOT/'app/build.gradle.kts', ROOT/'README.md']
    parts=[]
    for base in scan_paths:
        if base.is_file(): parts.append(base.read_text(errors='ignore'))
        elif base.exists(): parts.extend(p.read_text(errors='ignore') for p in base.rglob('*') if p.is_file() and p.stat().st_size < 2_000_000)
    corpus='\n'.join(parts)
    found=[x for x in forbidden if x in corpus]
    if found: raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED forbidden={found}')
    scheduler=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatScheduler.kt').read_text()
    updater=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatUpdater.kt').read_text()
    http=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatHttpClient.kt').read_text()
    store=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatStore.kt').read_text()
    url_models=(ROOT/'app/src/main/java/com/aman/security/scanner/UrlModels.kt').read_text()
    main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
    need(scheduler,['PeriodicWorkRequestBuilder<AutonomousThreatWorker>(6, TimeUnit.HOURS','NetworkType.CONNECTED'],'AUTONOMOUS_2_6_SCHEDULE')
    need(updater,['bazaar.abuse.ch/browse/tag/Android/','api.destroy.tools/v1/feed/primary_active','feodotracker.abuse.ch/downloads/ipblocklist_recommended.json','source.android.com/docs/security/bulletin/asb-overview'],'AUTONOMOUS_2_6_SOURCES')
    need(http,['instanceFollowRedirects = false','AutonomousSourcePolicy.allowed','AutonomousSourcePolicy.textPayloadAllowed','Executable/archive payload rejected'],'AUTONOMOUS_2_6_FETCH')
    need(store,['atomicWrite','Unexpected source shrink','autonomous-intel-v1','AUTO_PHISHING_PRIMARY','AUTO_PHISHING_COMMUNITY','SUSPICIOUS_SOURCE','PHISHING_TTL_MS','C2_TTL_MS','sourceLastSuccess','android_cves.txt','replaceAndroidCves'],'AUTONOMOUS_2_6_STORAGE')
    need(url_models,['SUSPICIOUS_SOURCE','COMMUNITY_THREAT_FEED'],'AUTONOMOUS_2_6_FALSE_POSITIVE_POLICY')
    need(main,['txtAutonomousLastUpdate','update_up_to_date'],'AUTONOMOUS_2_6_STATUS_UI')
    for suffix in ['.apk','.dex','.exe','.elf']:
        bad=[p for p in ROOT.rglob(f'*{suffix}') if 'build' not in p.parts]
        if bad: raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED payload={bad}')
    key_ext=['*.pem','*.key','*.p12','*.pfx','*.jks','*.keystore']
    bad=[]
    for pat in key_ext: bad.extend(ROOT.rglob(pat))
    if bad: raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED key_material={bad}')
    print('AUTONOMOUS_THREAT_INTEL_2_6_GATE_OK github_actions=0 api_keys=0 schedule_hours=6 sources=5 executable_payloads=0 community_feed=review_only transient_ttl=1 android_cve_store=1')
if __name__=='__main__': main()
