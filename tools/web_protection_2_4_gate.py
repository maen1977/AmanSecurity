#!/usr/bin/env python3
from pathlib import Path
import re, sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def need(path, token, message):
    text=(ROOT/path).read_text(encoding='utf-8')
    if token not in text: errors.append(message)

need('app/build.gradle.kts','versionName = "2.5.0"','version must be 2.5.0')
need('app/src/main/AndroidManifest.xml','.web.LinkGuardActivity','LinkGuardActivity missing')
need('app/src/main/AndroidManifest.xml','android.intent.action.VIEW','ACTION_VIEW handler missing')
need('app/src/main/AndroidManifest.xml','android.intent.category.BROWSABLE','BROWSABLE category missing')
need('app/src/main/AndroidManifest.xml','android:scheme="https"','HTTPS web guard missing')
need('app/src/main/java/com/aman/security/web/LinkGuardActivity.kt','WebProtectionDecision.BLOCK','known-threat block path missing')
need('app/src/main/java/com/aman/security/web/BrowserForwarder.kt','it.activityInfo.packageName != context.packageName','self-loop exclusion missing')
need('app/src/main/java/com/aman/security/web/BrowserForwarder.kt','genericWeb','generic-browser filtering missing')
need('app/src/main/java/com/aman/security/web/WebProtectionPolicy.kt','UrlRiskLevel.KNOWN_PHISHING, UrlRiskLevel.KNOWN_MALICIOUS -> WebProtectionDecision.BLOCK','known web threats must block')
need('app/src/main/java/com/aman/security/scanner/UrlScanner.kt','hostSuffixes(normalized.host)','boundary-safe host suffix lookup missing')
need('app/src/main/java/com/aman/security/scanner/UrlScanner.kt','UrlRiskSignal.PLAIN_HTTP in signals && UrlRiskSignal.SUSPICIOUS_KEYWORDS in signals','compound phishing scoring missing')
need('app/src/main/java/com/aman/security/scanner/UrlNormalizer.kt',"it == '\\\\'",'backslash ambiguity rejection missing')
manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text(encoding='utf-8')
if 'android.net.VpnService' in manifest or 'BIND_VPN_SERVICE' in manifest:
    errors.append('Phase 2.4 must not claim a VPN without a packet-forwarding implementation')
workflow=list((ROOT/'.github/workflows').glob('*.y*ml'))
if len(workflow)!=1: errors.append(f'exactly one workflow required, found {len(workflow)}')
if errors:
    print('WEB_PROTECTION_2_4_GATE_FAILED')
    for e in errors: print(' -',e)
    sys.exit(1)
print('WEB_PROTECTION_2_4_GATE_OK browser_role=1 local_scan=1 known_block=1 caution_confirm=1 self_loop_guard=1 vpn_claim=0 workflows=1')
