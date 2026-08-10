#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def need(path, token, msg):
    if token not in (ROOT/path).read_text(encoding='utf-8'): errors.append(msg)
need('app/src/main/AndroidManifest.xml','.web.LinkGuardActivity','LinkGuardActivity missing')
need('app/src/main/AndroidManifest.xml','android.intent.category.BROWSABLE','BROWSABLE missing')
need('app/src/main/java/com/aman/security/web/LinkGuardActivity.kt','WebProtectionDecision.BLOCK','known-threat block missing')
need('app/src/main/java/com/aman/security/web/BrowserForwarder.kt','it.activityInfo.packageName != context.packageName','self-loop guard missing')
need('app/src/main/java/com/aman/security/scanner/UrlScanner.kt','hostSuffixes(normalized.host)','boundary host matching missing')
need('app/src/main/java/com/aman/security/scanner/UrlNormalizer.kt',"it == '\\\\'",'backslash rejection missing')
manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text()
if 'android.net.VpnService' in manifest or 'BIND_VPN_SERVICE' in manifest: errors.append('incomplete VPN claim')
if errors:
 print('WEB_PROTECTION_2_4_GATE_FAILED'); [print(' - '+e) for e in errors]; sys.exit(1)
print('WEB_PROTECTION_2_4_GATE_OK local_link_guard=1 known_block=1 self_loop_guard=1 vpn_claim=0')
