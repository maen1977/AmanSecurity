#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
scanner=(ROOT/'app/src/main/java/com/aman/security/protection/ManualStorageFolderScanner.kt').read_text()
layout=(ROOT/'app/src/main/res/layout/activity_main.xml').read_text()
strings=(ROOT/'app/src/main/res/values/strings.xml').read_text()
strings_ar=(ROOT/'app/src/main/res/values-ar/strings.xml').read_text()

def need(ok,label):
    if not ok: raise SystemExit('MANUAL_STORAGE_SCAN_3_5_FAILED '+label)

need('ManualStorageFolderScanner' in scanner and 'DocumentsContract.buildChildDocumentsUriUsingTree' in scanner,'scanner_saf_tree_traversal')
need('visited >= ProtectionPolicy.MAX_DOCUMENTS_PER_RUN' in scanner and 'scanned >= ProtectionPolicy.MAX_SCAN_FILES_PER_RUN' in scanner,'scanner_resource_limits')
need('shouldCancel?.invoke() == true' in scanner and 'CancellationException' in scanner,'scanner_cancellation_support')
need('recordStore.recordScan(result)' in scanner and 'eventStore.add' in scanner,'scanner_persistence_and_events')

need('btnChooseStorageFolder' in layout and 'btnScanStorageFolder' in layout and 'txtStorageScanSelection' in layout and 'txtStorageScanResult' in layout,'ui_layout_elements')
need('manualStorageFolderPicker' in main and 'selectedStorageTreeUri' in main,'ui_state_management')
need('scanManualStorageFolder()' in main and 'ManualStorageFolderScanner' in main,'ui_scanner_integration')
need('takePersistableUriPermission' in main and 'STORAGE_SCAN_PREFERENCES' in main,'ui_saf_persistence')
need('scanCancelRequested = false' in main and 'activeScan = true' in main and 'setScanControlsEnabled(false)' in main,'ui_scan_lifecycle_lock')
need('it is CancellationException' in main and 'scan_cancelled_detail' in main,'ui_cancellation_feedback')

need('storage_scan_title' in strings and 'storage_scan_running' in strings and 'storage_scan_result' in strings,'strings_en_present')
need('storage_scan_title' in strings_ar and 'storage_scan_running' in strings_ar and 'storage_scan_result' in strings_ar,'strings_ar_present')

print('MANUAL_STORAGE_SCAN_3_5_OK saf_tree=1 limits=1 cancellation=1 persistence=1 ui_binding=1 saf_persistence=1 strings=1')
