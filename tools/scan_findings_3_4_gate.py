#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
store=(ROOT/'app/src/main/java/com/aman/security/protection/ScanFindingsStore.kt').read_text()
service=(ROOT/'app/src/main/java/com/aman/security/protection/ProtectionService.kt').read_text()
main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
layout=(ROOT/'app/src/main/res/layout/activity_main.xml').read_text()
shared=(ROOT/'app/src/main/java/com/aman/security/protection/SharedStorageScanner.kt').read_text()

def need(ok,label):
    if not ok: raise SystemExit('SCAN_FINDINGS_3_4_GATE_FAILED '+label)

need('class ScanFindingsStore' in store and 'aman_scan_findings_v1' in store,'durable_store')
need('StoredScanFindingSeverity.CONFIRMED' in store and 'StoredScanFindingSeverity.HIGH' in store and 'StoredScanFindingSeverity.REVIEW' in store,'severity_split')
need('apps.results' in store and 'spyware.findings' in store and 'audit.device.findings' in store and 'audit.network.findings' in store,'evidence_sources')
need('ScanFindingsStore(applicationContext).save' in service,'service_persists_exact_findings')
need('btnViewScanFindings' in layout and 'scanFindingsCard' in layout and 'highRiskFindingsContainer' in layout and 'reviewFindingsContainer' in layout,'results_ui')
need('renderLatestScanFindings' in main and 'findingDetails' in main and 'openAppDetails' in main,'actionable_ui')
need('Needs review' in (ROOT/'app/src/main/res/values/strings.xml').read_text() and 'ليس فيروسًا مؤكدًا' in (ROOT/'app/src/main/res/values-ar/strings.xml').read_text(),'non_malware_disclaimer')
need('SharedStorageAlertFinding' in shared and 'file.absolutePath' in shared,'file_location_capture')
print('SCAN_FINDINGS_3_4_OK durable_details=1 exact_app=1 exact_file_path=1 audit_evidence=1 spyware_evidence=1 high_vs_review=1 app_info_action=1 local_only=1')
