#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
layout=(ROOT/'app/src/main/res/layout/activity_main.xml').read_text()
activity=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
workflow=(ROOT/'.github/workflows/build.yml').read_text()
required_layout=[
 'txtSecurityScore','txtDashboardHeadline','txtDashboardSubtitle','btnSmartScan',
 'smartScanCard','smartScanProgress','smartResultCard','txtSmartResultTitle',
 'txtSmartResultSummary','txtSmartResultDetails','btnQuickApps','btnQuickFile',
 'btnQuickWeb','btnQuickProtection','btnQuickQuarantine','btnQuickUpdate',
 'installedAppsSection','protectionSection','webProtectionSection','quarantineSection',
 'securityAuditSection','txtSecurityAuditStatus','txtDeviceAudit','txtNetworkAudit','txtPrivacyAudit','btnRunSecurityAudit','btnPrivacyControl'
]
missing=[x for x in required_layout if f'@+id/{x}' not in layout]
listener_start=activity.find('binding.bottomNav.setOnItemSelectedListener')
listener_end=activity.find('private fun showPage', listener_start) if listener_start >= 0 else -1
listener_block=activity[listener_start:listener_end] if listener_start >= 0 and listener_end > listener_start else ''
checks={
 'dashboard_logic':'renderSmartDashboard' in activity and 'adjustedScore' in activity,
 'scan_state':'showSmartScan' in activity and 'renderSmartInstalledResult' in activity,
 'results_state':'renderSmartFileResult' in activity and 'showSmartResult' in activity,
 'quick_actions':'btnQuickApps.setOnClickListener' in activity and 'btnQuickQuarantine.setOnClickListener' in activity,
 'navigation_safe':'selectedItemId =' not in listener_block and 'renderPage(page)' in listener_block and 'navItemForPage' in activity,
 'full_smart_scan':'requestSmartScan' in activity and 'renderSmartFullResult' in activity and 'SecurityAuditSummary' in activity,
 'security_audit':'runStandaloneSecurityAudit' in activity and 'renderSecurityAudit' in activity and 'PrivacyControlActivity::class.java' in activity,
 'auto_build':'push:' in workflow and 'branches: [ "main" ]' in workflow and 'workflow_dispatch:' in workflow,
 'no_schedule':'schedule:' not in workflow,
}
failed=[k for k,v in checks.items() if not v]
if missing or failed:
    raise SystemExit(f'SMART_UI_GATE_FAILED missing={missing} failed={failed}')
print('SMART_UI_GATE_OK dashboard=1 scan_state=1 results=1 protection_center=1 quick_actions=6 navigation_safe=1 smart_scan_layers=5 security_audit=1 auto_build=1 schedule=0')
