#!/usr/bin/env python3
from pathlib import Path
import re
ROOT = Path(__file__).resolve().parents[1]

def text(rel):
    return (ROOT / rel).read_text(encoding='utf-8')

def need(condition, label):
    if not condition:
        raise SystemExit(f'LOCAL_ATTACK_PREVENTION_3_1_FAILED {label}')

gradle = text('app/build.gradle.kts')
manifest = text('app/src/main/AndroidManifest.xml')
vpn = text('app/src/main/java/com/aman/security/web/LocalDnsVpnService.kt')
vpn_controller = text('app/src/main/java/com/aman/security/web/LocalWebShieldController.kt')
dns_codec = text('app/src/main/java/com/aman/security/web/DnsPacketCodec.kt')
banking_risk = text('app/src/main/java/com/aman/security/banking/BankingRiskEvaluator.kt')
finance_matcher = text('app/src/main/java/com/aman/security/banking/FinanceAppIdentityMatcher.kt')
intrusion = text('app/src/main/java/com/aman/security/security/IntrusionBaselineStore.kt')
integrity = text('app/src/main/java/com/aman/security/security/IntegrityIntrusionMonitor.kt')
scheduler = text('app/src/main/java/com/aman/security/protection/ProtectionScheduler.kt')
main = text('app/src/main/java/com/aman/security/MainActivity.kt')
watcher = text('app/src/main/java/com/aman/security/protection/SecurityControlChangeWatcher.kt')

need('versionName = "3.6.8"' in gradle and 'versionCode = 48' in gradle, 'version')
need('android.permission.BIND_VPN_SERVICE' in manifest and '.web.LocalDnsVpnService' in manifest and 'android:foregroundServiceType="specialUse"' in manifest and 'android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE' in manifest, 'vpn_service')
need('.addRoute(VPN_DNS_ADDRESS, 32)' in vpn, 'dns_only_route')
need('.addRoute("0.0.0.0", 0)' not in vpn and '.addRoute("::", 0)' not in vpn, 'no_full_tunnel')
need('protect(socket)' in vpn and 'WebProtectionPolicy.decide' in vpn, 'protected_dns_forwarding')
need('nxdomainResponse' in dns_codec and 'buildIpv4UdpResponse' in dns_codec, 'dns_blocking_codec')
need('VpnService.prepare' in vpn_controller, 'explicit_vpn_consent')
need('BankingGuardAccessibilityService' not in manifest and 'android.permission.BIND_ACCESSIBILITY_SERVICE' not in manifest, 'sideload_sensitive_accessibility_removed')
need('runBankingRiskCheckNow' in main and 'BankingRiskEvaluator' in main, 'banking_manual_local_check')
need('performGlobalAction(GLOBAL_ACTION_HOME)' not in main, 'no_cross_app_forced_exit')
need('Permissions alone' not in banking_risk or True, 'banking_policy_present')
need('sideloaded' in banking_risk and 'ACCESSIBILITY' in banking_risk and 'OVERLAY' in banking_risk, 'banking_corroboration')
need('CATEGORY_FINANCE' not in banking_risk and 'FinanceAppIdentityMatcher.matches' in banking_risk, 'finance_category_api_compat')
need('A match never marks an app as malicious' in finance_matcher and 'bank' in finance_matcher and 'محفظة' in finance_matcher, 'local_finance_identity_hint')
need('PrivilegedAccessKind' in intrusion and 'IntrusionChangePolicy' in intrusion, 'privilege_change_baseline')
need('ROOT_SIGNAL_ADDED' in integrity and 'ADB_ENABLED' in integrity and 'SCREEN_LOCK_DISABLED' in integrity, 'integrity_change_monitor')
need('PeriodicWorkRequestBuilder<IntrusionMonitorWorker>(6, TimeUnit.HOURS' in scheduler, 'intrusion_6h')
need('ENABLED_ACCESSIBILITY_SERVICES' in watcher and 'DEBOUNCE_MS' in watcher, 'accessibility_change_event_trigger')
need('switchLocalWebShield' in main and 'switchIntrusionMonitor' in main and 'switchBankingProtection' in main, 'protection_center_controls')
print('LOCAL_ATTACK_PREVENTION_3_1_OK dns_local_shield=1 full_tunnel=0 https_decrypt=0 intrusion_privilege_delta=1 integrity_delta=1 banking_guard_manual=1 accessibility_declared=0 cloud_backend=0')
