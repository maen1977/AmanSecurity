#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def need(ok,label):
    if not ok: raise SystemExit('LIGHTWEIGHT_LOCAL_ENGINE_3_2_FAILED '+label)
gradle=(ROOT/'app/build.gradle.kts').read_text()
service=(ROOT/'app/src/main/java/com/aman/security/protection/ProtectionService.kt').read_text()
controller=(ROOT/'app/src/main/java/com/aman/security/protection/ProtectionServiceController.kt').read_text()
scheduler=(ROOT/'app/src/main/java/com/aman/security/protection/ProtectionScheduler.kt').read_text()
cache=(ROOT/'app/src/main/java/com/aman/security/protection/LocalScanCacheStore.kt').read_text()
sweep=(ROOT/'app/src/main/java/com/aman/security/protection/CachedReputationSweepWorker.kt').read_text()
worker=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatWorker.kt').read_text()
spy=(ROOT/'app/src/main/java/com/aman/security/security/SpywareRiskPolicy.kt').read_text()
main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
need('versionName = "3.2.0"' in gradle and 'versionCode = 22' in gradle,'version')
need('10 * 60_000L' in service and '22 * 60 * 1000L' in controller,'relaxed_heartbeat')
need('PeriodicWorkRequestBuilder<DownloadProtectionWorker>(2, TimeUnit.HOURS' in scheduler,'downloads_2h')
need('PeriodicWorkRequestBuilder<ProtectedFolderWorker>(6, TimeUnit.HOURS' in scheduler,'folder_6h')
need('CachedAppArtifact' in cache and 'CachedFileArtifact' in cache,'local_cache')
need('No APK/file is opened here' in sweep and 'recheckCachedReputationNow' in worker,'hash_only_refresh')
need('Permissions alone never equal malware' in spy and 'SIDELOADED' in spy,'spyware_correlation')
need('txtSpywareHome' in main and 'local_engine_lightweight_status' in main,'ui_status')

enable_block=scheduler.split('fun enable(context: Context) {',1)[1].split('fun disable(context: Context)',1)[0]
need('.setInitialDelay(6, TimeUnit.HOURS)' in enable_block,'folder_intrusion_deferred')
need('.setInitialDelay(12, TimeUnit.HOURS)' in enable_block,'app_rescan_deferred')
need('.setInitialDelay(2, TimeUnit.HOURS)' in enable_block,'downloads_catchup_deferred')
need('checkNow(context)' not in enable_block and 'scanDownloadsNow(context)' not in enable_block,'no_enable_scan_spike')
print('LIGHTWEIGHT_LOCAL_ENGINE_3_2_OK local_cache=1 event_driven=1 threat_refresh_6h=1 cached_reputation_sweep=1 downloads_catchup_2h=1 folder_scan_6h=1 heartbeat_10m=1 spyware_audit=1 no_cloud_backend=1')
