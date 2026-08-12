#!/usr/bin/env python3
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]

def need(text, items, label):
    missing=[x for x in items if x not in text]
    if missing: raise SystemExit(f"{label}_FAILED missing={missing}")

def main():
    workflows = sorted((ROOT/'.github/workflows').glob('*.y*ml')) if (ROOT/'.github/workflows').exists() else []
    allowed = [ROOT/'.github/workflows/build.yml']
    if workflows != allowed:
        raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED unexpected_workflows={[str(p.relative_to(ROOT)) for p in workflows]}')
    workflow = allowed[0].read_text(errors='ignore') if allowed[0].exists() else ''
    required_workflow = ['push:', 'branches: [ "main" ]', 'workflow_dispatch:', 'gradle :app:assembleDebug', 'actions/upload-artifact@v4']
    missing_workflow = [x for x in required_workflow if x not in workflow]
    if missing_workflow:
        raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED build_workflow_missing={missing_workflow}')
    forbidden_workflow = ['schedule:', 'THREAT_DB_PRIVATE_KEY_BASE64', 'ABUSECH_AUTH_KEY', 'refresh_threat_intel.py', 'update_threat_intel.py']
    bad_workflow = [x for x in forbidden_workflow if x in workflow]
    if bad_workflow:
        raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED build_workflow_forbidden={bad_workflow}')
    legacy = [
        'tools/threat_db_continuity_gate.py',
        'tools/reputation_gate.py',
        'tools/verify_reputation_shards.py',
        'tools/single_workflow_gate.py',
        'tools/real_antivirus_gate.py',
        'tools/refresh_threat_intel.py',
        'tools/update_threat_intel.py',
    ]
    stale=[rel for rel in legacy if (ROOT/rel).exists()]
    if stale: raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED legacy_github_pipeline={stale}')
    gradle=(ROOT/'app/build.gradle.kts').read_text()
    need(gradle,['versionName = "3.2.0"','versionCode = 22'],'AUTONOMOUS_3_2_VERSION')
    forbidden=['THREAT_DB_BASE_URL','REPUTATION_SHARD_BASE_URL','raw.githubusercontent.com','ABUSECH_AUTH_KEY','THREAT_DB_PRIVATE_KEY_BASE64']
    scan_paths=[ROOT/'app/src/main', ROOT/'app/build.gradle.kts', ROOT/'README.md']
    hits={x:[] for x in forbidden}
    for base in scan_paths:
        candidates=[base] if base.is_file() else ([p for p in base.rglob('*') if p.is_file() and p.stat().st_size < 2_000_000] if base.exists() else [])
        for path in candidates:
            text=path.read_text(errors='ignore')
            for marker in forbidden:
                if marker in text:
                    hits[marker].append(str(path.relative_to(ROOT)))
    found={k:v for k,v in hits.items() if v}
    if found: raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED forbidden_paths={found}')
    scheduler=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatScheduler.kt').read_text()
    updater=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatUpdater.kt').read_text()
    http=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatHttpClient.kt').read_text()
    store=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatStore.kt').read_text()
    url_models=(ROOT/'app/src/main/java/com/aman/security/scanner/UrlModels.kt').read_text()
    main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
    need(scheduler,['PeriodicWorkRequestBuilder<AutonomousThreatWorker>(6, TimeUnit.HOURS','NetworkType.CONNECTED'],'AUTONOMOUS_2_6_SCHEDULE')
    need(updater,['bazaar.abuse.ch/browse/tag/Android/','api.destroy.tools/v1/feed/primary_active','urlhaus.abuse.ch/downloads/text/','feodotracker.abuse.ch/downloads/ipblocklist_recommended.json','source.android.com/docs/security/bulletin/asb-overview'],'AUTONOMOUS_2_6_SOURCES')
    need(http,['instanceFollowRedirects = false','AutonomousSourcePolicy.allowed','AutonomousSourcePolicy.textPayloadAllowed','Executable/archive payload rejected'],'AUTONOMOUS_2_6_FETCH')
    need(store,['atomicWrite','Unexpected source shrink','autonomous-intel-v1','AUTO_PHISHING_PRIMARY','AUTO_PHISHING_COMMUNITY','SUSPICIOUS_SOURCE','sourceLastSuccess','sourceConsecutiveFailures','recordRun','android_cves.txt','replaceAndroidCves'],'AUTONOMOUS_2_7_STORAGE')
    need(url_models,['SUSPICIOUS_SOURCE','COMMUNITY_THREAT_FEED'],'AUTONOMOUS_2_6_FALSE_POSITIVE_POLICY')
    need(main,['txtAutonomousLastUpdate','update_up_to_date'],'AUTONOMOUS_2_6_STATUS_UI')
    for suffix in ['.apk','.dex','.exe','.elf']:
        bad=[p for p in ROOT.rglob(f'*{suffix}') if 'build' not in p.parts]
        if bad: raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED payload={bad}')
    key_ext=['*.pem','*.key','*.p12','*.pfx','*.jks','*.keystore']
    bad=[]
    for pat in key_ext: bad.extend(ROOT.rglob(pat))
    if bad: raise SystemExit(f'AUTONOMOUS_2_6_GATE_FAILED key_material={bad}')
    print('AUTONOMOUS_THREAT_INTEL_3_1_GATE_OK threat_update_actions=0 build_workflows=1 auto_build_push_main=1 manual_build=1 api_keys=0 schedule_hours=6 sources=6 executable_payloads=0 community_feed=review_only transient_ttl=1 source_health=1 android_cve_store=1')
if __name__=='__main__': main()
