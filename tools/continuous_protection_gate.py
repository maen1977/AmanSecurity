#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def need(c,m):
    if not c: errors.append(m)
def text(p): return (ROOT/p).read_text(encoding='utf-8')
build=text('app/build.gradle.kts')
scheduler=text('app/src/main/java/com/aman/security/protection/ProtectionScheduler.kt')
worker=text('app/src/main/java/com/aman/security/protection/InstalledAppsRescanWorker.kt')
update=text('app/src/main/java/com/aman/security/update/ThreatUpdateWorker.kt')
newpkg=text('app/src/main/java/com/aman/security/protection/NewPackageScanWorker.kt')
policy=text('app/src/main/java/com/aman/security/protection/AppRescanPolicy.kt')
workflow=text('.github/workflows/main.yml')
need('versionCode = 13' in build and 'versionName = "2.3.0"' in build,'2.3.0/code13')
need('PeriodicWorkRequestBuilder<InstalledAppsRescanWorker>(24, TimeUnit.HOURS' in scheduler,'daily installed-app reputation rescan')
need('setRequiresBatteryNotLow(true)' in scheduler and 'setRequiresStorageNotLow(true)' in scheduler,'battery/storage constraints for periodic app rescan')
need('scanUserApps(deep = false)' in worker,'lightweight reputation/hash rescan')
need('appLedger()' in worker and 'saveAppLedger' in worker,'app detection ledger')
need('AppRescanPolicy.shouldNotify' in worker and 'AppRescanPolicy.shouldNotify' in newpkg,'duplicate-alert suppression')
need('is ThreatDatabaseUpdater.Result.Updated' in update and 'rescanInstalledAppsNow' in update,'rescan after signed DB update')
need('result.riskLevel != AppRiskLevel.HIGH' in policy and 'KNOWN_THREAT' in policy,'high/known only notifications')
need('tools/threat_db_continuity_gate.py' in workflow,'threat DB continuity gate in CI')
need('benchmarks/false_positive_stress.csv' in workflow,'false-positive stress benchmark in CI')
need(len(list((ROOT/'.github/workflows').glob('*.y*ml'))) == 1,'single workflow')
if errors:
    print('CONTINUOUS_PROTECTION_GATE_FAILED')
    for e in errors: print(' -',e)
    sys.exit(1)
print('CONTINUOUS_PROTECTION_GATE_OK version=2.3.0 daily_reputation_rescan=1 post_db_update_rescan=1 duplicate_alert_suppression=1 false_positive_stress=1 continuity_floor=1')
