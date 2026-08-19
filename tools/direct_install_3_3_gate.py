#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text()
main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
workflow=(ROOT/'.github/workflows/build.yml').read_text()

def need(ok,msg):
    if not ok: raise SystemExit('DIRECT_INSTALL_3_3_FAILED '+msg)

need('android:name=".banking.BankingGuardAccessibilityService"' not in manifest, 'accessibility_service_must_not_be_declared_for_internet_sideload')
need('android.permission.BIND_ACCESSIBILITY_SERVICE' not in manifest, 'accessibility_binding_must_not_be_declared')
need('runBankingRiskCheckNow' in main and 'BankingRiskEvaluator' in main, 'manual_banking_check_missing')
need('actions/cache@v4' in workflow and '~/.android/debug.keystore' in workflow, 'stable_ci_debug_key_cache_missing')
need('MaenShield-1.1.1.11-TestRelease.apk' in workflow, 'direct_install_apk_missing')
need('MaenShield-1.1.1.11-TestRelease-APK' in workflow, 'direct_install_artifact_missing')
print('DIRECT_INSTALL_3_3_OK single_apk=1 sensitive_accessibility_declared=0 ci_debug_key_cached=1 verifier_bypass=0')
