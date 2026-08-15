#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def text(rel): return (ROOT/rel).read_text(encoding='utf-8')
def need(ok,label):
    if not ok: raise SystemExit('ATTACK_DETECTION_CENTER_3_2_FAILED '+label)

gradle=text('app/build.gradle.kts')
center=text('app/src/main/java/com/aman/security/security/AttackDetectionCenter.kt')
policy=text('app/src/main/java/com/aman/security/security/AttackDetectionPolicy.kt')
main=text('app/src/main/java/com/aman/security/MainActivity.kt')
layout=text('app/src/main/res/layout/activity_main.xml')
notifier=text('app/src/main/java/com/aman/security/protection/ProtectionNotifier.kt')
scheduler=text('app/src/main/java/com/aman/security/protection/ProtectionScheduler.kt')
test=text('app/src/test/java/com/aman/security/security/AttackDetectionPolicyTest.kt')

need('versionName = "3.6.0"' in gradle and 'versionCode = 40' in gradle,'version')
need('AttackDetectionLevel' in policy and 'AttackDetectionPolicy' in policy and 'RECENT_SIGNAL_WINDOW_MS' in center,'local_aggregation')
need('ProtectionActivityStore' in center and 'ProtectionActivityKind.WEB_SHIELD' in center,'existing_signal_sources')
need('entry.kind != ProtectionActivityKind.WEB_SHIELD' in center,'blocked_web_is_not_compromise')
for forbidden in ['WorkManager','Worker','Thread(','Handler(','VpnService','FileObserver']:
    need(forbidden not in center,'no_background_engine:'+forbidden)
need('attackDetectionCard' in layout and 'txtAttackDetectionLevel' in layout and 'btnAttackCheckNow' in layout,'compact_center_ui')
need('renderAttackDetectionCenter()' in main and 'txtAttackHome' in main,'home_and_center_status')
need('AttackDetectionCenter(context).snapshot()' in notifier,'persistent_status_correlation')
need('updateProtectionStatus(context)' in notifier,'event_refreshes_status')
enable_block=scheduler.split('fun enable(context: Context) {',1)[1].split('fun disable(context: Context)',1)[0]
need('checkNow(context)' not in enable_block and 'scanDownloadsNow(context)' not in enable_block,'no_enable_scan_spike')
need('.setInitialDelay(12, TimeUnit.HOURS)' in enable_block and '.setInitialDelay(2, TimeUnit.HOURS)' in enable_block,'deferred_catchup')
need('blockedOrReviewSignalIsWatchNotCompromise' in test and 'corroboratedCriticalSignalWins' in test,'policy_regression')
print('ATTACK_DETECTION_CENTER_3_2_OK local_correlation=1 extra_worker=0 extra_polling=0 web_block_is_watch=1 critical_local_signals=1 persistent_status=1 deferred_enable_scans=1')
