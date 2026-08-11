#!/usr/bin/env python3
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text()
main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
service=(ROOT/'app/src/main/java/com/aman/security/protection/ProtectionService.kt').read_text()
scheduler=(ROOT/'app/src/main/java/com/aman/security/protection/ProtectionScheduler.kt').read_text()
downloads=(ROOT/'app/src/main/java/com/aman/security/protection/DownloadProtectionScanner.kt').read_text()
strings=(ROOT/'app/src/main/res/values/strings.xml').read_text()
layout=(ROOT/'app/src/main/res/layout/activity_main.xml').read_text()
notifier=(ROOT/'app/src/main/java/com/aman/security/protection/ProtectionNotifier.kt').read_text()

def need(ok,label):
    if not ok: raise SystemExit('REALTIME_ANTIVIRUS_GATE_FAILED '+label)

need('android.permission.FOREGROUND_SERVICE' in manifest,'fgs_permission')
need('android.permission.POST_NOTIFICATIONS' in manifest,'notifications_permission')
need('android.permission.FOREGROUND_SERVICE_SPECIAL_USE' in manifest,'fgs_special_use_permission')
need('android:foregroundServiceType="specialUse"' in manifest,'fgs_type')
need('android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE' in manifest,'fgs_subtype_disclosure')
need('.protection.ProtectionService' in manifest,'fgs_service')
need('android.permission.RECEIVE_BOOT_COMPLETED' in manifest and '.protection.ProtectionBootReceiver' in manifest,'boot_restore')
need('android.intent.action.PACKAGE_ADDED' in manifest and 'android.intent.action.PACKAGE_REPLACED' in manifest,'package_events')
need('android.permission.MANAGE_EXTERNAL_STORAGE' in manifest,'antivirus_file_access')
need('android.permission.WRITE_EXTERNAL_STORAGE' not in manifest,'legacy_write_storage_forbidden')
read_match=re.search(r'<uses-permission\s+android:name="android\.permission\.READ_EXTERNAL_STORAGE"\s+android:maxSdkVersion="(\d+)"\s*/>',manifest,re.S)
need(read_match is not None and int(read_match.group(1)) <= 29,'legacy_read_storage_bounded')
need('file_access_disclosure_body' in strings and 'Files are not uploaded' in strings,'file_access_disclosure')
need('ServiceCompat.startForeground' in service and 'setOngoing(true)' in notifier,'persistent_status')
need('ContextCompat.checkSelfPermission' in notifier and 'Manifest.permission.POST_NOTIFICATIONS' in notifier and 'SecurityException' in notifier,'notification_permission_guard')
need('FileObserver' in service and 'scanDownloadedFile' in service,'downloads_realtime_observer')
need('PeriodicWorkRequestBuilder<DownloadProtectionWorker>(15, TimeUnit.MINUTES)' in scheduler,'downloads_catchup')
need('ledger' in downloads and 'FileScanner' in downloads,'downloads_local_scan')
need('requestFullScan()' in main and 'SharedStorageScanner' in main,'manual_full_scan')
need('btnFullScan' in layout and 'btnScanDownloads' in layout and 'txtProtectionServiceHealth' in layout,'protection_ui')
need('ProtectionServiceController.isHealthy(this)' in main,'service_health_ui')
print('REALTIME_ANTIVIRUS_GATE_OK fgs=1 persistent_status=1 notification_permission_guard=1 boot_restore=1 package_monitor=1 downloads_realtime=1 downloads_catchup=1 full_scan=1 all_files_antivirus_disclosure=1')
