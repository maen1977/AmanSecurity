#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
service=(ROOT/'app/src/main/java/com/aman/security/protection/ProtectionService.kt').read_text()
controller=(ROOT/'app/src/main/java/com/aman/security/protection/ProtectionServiceController.kt').read_text()
scan_store=(ROOT/'app/src/main/java/com/aman/security/protection/ScanSessionStore.kt').read_text()
main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
scheduler=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatScheduler.kt').read_text()
worker=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatWorker.kt').read_text()
update_store=(ROOT/'app/src/main/java/com/aman/security/autonomous/ThreatUpdateStateStore.kt').read_text()
manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text()
gradle=(ROOT/'app/build.gradle.kts').read_text()
colors=(ROOT/'app/src/main/res/values/colors.xml').read_text()

def need(ok,label):
    if not ok: raise SystemExit('CORE_RUNTIME_3_4_GATE_FAILED '+label)

need('versionName = "1.1.1.1"' in gradle and 'versionCode = 74' in gradle,'version')
need('ACTION_SCAN' in service and 'PersistentScanMode.QUICK' in service and 'PersistentScanMode.FULL' in service,'service_scans')
need('START_STICKY' in service and 'onTaskRemoved' in service,'service_persistence')
need('ScanSessionStore' in scan_store and 'PersistentScanState.RUNNING' in scan_store and 'PersistentScanState.COMPLETED' in scan_store,'durable_scan_state')
need('startScan(context: Context' in controller and 'cancelScan(context: Context)' in controller,'scan_controller')
need('startPersistentScan(PersistentScanMode.QUICK)' in main,'quick_scan_persistent')
need('startPersistentScan(PersistentScanMode.SMART)' in main,'smart_scan_persistent')
need('startPersistentScan(PersistentScanMode.FULL)' in main,'full_scan_persistent')
need('renderPersistentOperations' in main and 'OPERATION_UI_POLL_MS = 1_200L' in main and 'ProtectionServiceController.recoverPendingScan(this)' in main,'ui_reconnect')
need('AutonomousThreatScheduler.updateNow(this)' in main,'manual_update_worker_owned')
need('ThreatUpdateStateStore' in worker and '.update { progress ->' in worker and 'state.progress(progress)' in worker,'update_progress')
need('ExistingWorkPolicy.REPLACE' in scheduler and 'manualNetworkConstraints' in scheduler,'manual_update_immediate')
need('android:stopWithTask="false"' in manifest,'task_close_does_not_stop_service')
need('HEARTBEAT_MS = 10 * 60_000L' in service,'light_heartbeat')
need('AmanPersistentScan' in service and 'Thread.NORM_PRIORITY - 1' in service,'low_priority_scan_thread')
need('#00A884' in colors and '#3D6DFF' in colors,'vivid_palette')
print('CORE_RUNTIME_3_4_OK persistent_fgs=1 durable_scan=1 quick=1 smart=1 full=1 update_workmanager=1 update_progress=1 task_close_safe=1 heartbeat_10m=1 vivid_ui=1')
