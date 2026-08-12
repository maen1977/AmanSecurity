#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text()

def need(ok,msg):
    if not ok: raise SystemExit('PLAY_PROTECT_SIDELOAD_FAILED '+msg)

# Google Play Protect Enhanced Fraud Protection automatically blocks internet-sideloaded
# apps that declare these high-risk capabilities. Aman does not need SMS or notification
# listener access, and the sideload build uses manual banking checks instead of Accessibility.
for forbidden in [
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_SMS',
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.accessibilityservice.AccessibilityService',
    'BankingGuardAccessibilityService',
]:
    need(forbidden not in manifest, 'forbidden_sensitive_capability:'+forbidden)
print('PLAY_PROTECT_SIDELOAD_OK sms=0 notification_listener=0 accessibility=0 verifier_bypass=0')
