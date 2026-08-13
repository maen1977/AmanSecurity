#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def text(rel): return (ROOT/rel).read_text(encoding='utf-8')
def need(ok,label):
    if not ok: raise SystemExit('DATA_EXFILTRATION_GUARD_3_3_FAILED '+label)

gradle=text('app/build.gradle.kts')
manifest=text('app/src/main/AndroidManifest.xml')
service=text('app/src/main/java/com/aman/security/protection/ProtectionService.kt')
guard=text('app/src/main/java/com/aman/security/security/DataExfiltrationGuard.kt')
policy=text('app/src/main/java/com/aman/security/security/DataExfiltrationPolicy.kt')
access=text('app/src/main/java/com/aman/security/security/DataExfiltrationAccess.kt')
vpn=text('app/src/main/java/com/aman/security/web/LocalDnsVpnService.kt')
cache=text('app/src/main/java/com/aman/security/web/RecentDnsObservationCache.kt')
monitor=text('app/src/main/java/com/aman/security/security/HighRiskNetworkContactMonitor.kt')
main=text('app/src/main/java/com/aman/security/MainActivity.kt')
layout=text('app/src/main/res/layout/activity_main.xml')
center=text('app/src/main/java/com/aman/security/security/AttackDetectionCenter.kt')
preferences=text('app/src/main/java/com/aman/security/protection/ProtectionPreferences.kt')
test=text('app/src/test/java/com/aman/security/security/DataExfiltrationPolicyTest.kt')

need('versionName = "3.5.0"' in gradle and 'versionCode = 30' in gradle,'version')
need('android.permission.PACKAGE_USAGE_STATS' in manifest,'usage_access_manifest')
need('NetworkStatsManager' in guard and 'TrafficStats.getTotalTxBytes()' in guard,'two_stage_stats')
need('if (totalTx < 0L) return null' in guard and 'totalTx == TrafficStats.UNSUPPORTED' not in guard,'trafficstats_long_compat')
need(all(key in preferences for key in [
    'KEY_DATA_EXFIL_GUARD_ENABLED',
    'KEY_LAST_DATA_EXFIL_PROBE_AT',
    'KEY_LAST_DATA_EXFIL_DEVICE_TX',
    'KEY_LAST_DATA_EXFIL_DETAILED_AUDIT_AT',
    'KEY_LAST_DATA_EXFIL_CHECK_AT',
    'KEY_LAST_DATA_EXFIL_REVIEW_COUNT',
    'KEY_LAST_DATA_EXFIL_HIGH_COUNT',
    'KEY_LAST_DATA_EXFIL_TOP_PACKAGE',
    'KEY_LAST_DATA_EXFIL_TOP_BYTES',
]),'preference_keys_declared')
need('QUICK_UPLOAD_TRIGGER_BYTES = 8L * MIB' in guard and 'PERIODIC_DETAILED_AUDIT_MS = 6L * 60L * 60L * 1000L' in guard,'lightweight_cadence')
need('newSingleThreadExecutor' in service and 'Thread.MIN_PRIORITY' in service,'low_priority_worker')
need('maybeRunDataExfiltrationGuard()' in service and 'HEARTBEAT_MS = 10 * 60_000L' in service,'piggyback_existing_heartbeat')
need('Worker' not in guard and 'WorkManager' not in guard and 'VpnService' not in guard,'no_new_background_surface')
need('Upload volume by itself is never treated as theft' in policy,'false_positive_policy')
need('systemApp || input.backgroundTxBytes < 8 * MIB' in policy,'system_app_guard')
need('getConnectionOwnerUid' in vpn and 'RecentDnsObservationCache.record' in vpn and 'highRiskNetworkContactMonitor.onDnsContact' in vpn,'dns_uid_correlation')
need('Nothing is written to disk' in cache,'memory_only_dns_metadata')
need('SpywareReviewLevel.HIGH' in monitor and 'does not infer that data was transferred' in monitor,'immediate_high_risk_contact')
need('dataExfiltrationGuardActive' in center and 'ProtectionActivityKind.DATA_EXFILTRATION' in center,'attack_center_integration')
need('switchDataExfilGuard' in layout and 'btnDataUsageAccess' in layout and 'btnRunDataExfilCheck' in layout,'ui_controls')
need('DataExfiltrationAccess.isGranted' in main and 'ACTION_USAGE_ACCESS_SETTINGS' in main,'explicit_user_access')
need('largeUploadAloneIsNotDataTheft' in test and 'corroboratedSideloadedControllerWithBackgroundUploadIsHigh' in test,'regression_tests')
print('DATA_EXFILTRATION_GUARD_3_3_OK local_only=1 quick_probe=10m detailed_on_burst_or_6h=1 high_risk_dns_event_alert=1 payload_inspection=0 dns_memory_cache=1 usage_access=explicit no_new_worker=1')
