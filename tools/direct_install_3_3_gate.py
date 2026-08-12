#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text()
main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
workflow=(ROOT/'.github/workflows/build.yml').read_text()

def need(ok,msg):
    if not ok: raise SystemExit('DIRECT_INSTALL_3_3_FAILED '+msg)

need('android:name=".banking.BankingGuardAccessibilityService"' in manifest, 'banking_service_missing')
block=manifest.split('android:name=".banking.BankingGuardAccessibilityService"',1)[1].split('</service>',1)[0]
need('android:enabled="false"' in block, 'banking_service_must_be_disabled_at_install')
need('setBankingAccessibilityComponentEnabled(true)' in main, 'explicit_enable_missing')
need('setBankingAccessibilityComponentEnabled(false)' in main, 'explicit_disable_missing')
need('actions/cache@v4' in workflow and '~/.android/debug.keystore' in workflow, 'stable_ci_debug_key_cache_missing')
need('AmanSecurity-3.3.0-DirectInstall.apk' in workflow, 'direct_install_apk_missing')
need('AmanSecurity-3.3.0-DirectInstall-APK' in workflow, 'direct_install_artifact_missing')
print('DIRECT_INSTALL_3_3_OK single_apk=1 privileged_component_default_off=1 ci_debug_key_cached=1 verifier_bypass=0')
