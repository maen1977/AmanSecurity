#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def read(path): return (ROOT/path).read_text(encoding='utf-8')
def need(cond,msg):
    if not cond: errors.append(msg)
service=read('app/src/main/java/com/aman/security/web/LocalDnsVpnService.kt')
selftest=read('app/src/main/java/com/aman/security/web/WebShieldSelfTest.kt')
scanner=read('app/src/main/java/com/aman/security/scanner/UrlScanner.kt')
official=read('app/src/main/java/com/aman/security/scanner/OfficialWebTestIndicators.kt')
main=read('app/src/main/java/com/aman/security/MainActivity.kt')
layout=read('app/src/main/res/layout/activity_main.xml')
gradle=read('app/build.gradle.kts')
need('versionName = "3.4.3"' in gradle and 'versionCode = 26' in gradle,'version')
need('WebShieldSelfTestPolicy.isSelfTestHost' in service,'local test decision missing')
need('WebProtectionDecision.TEST' in service and 'recordTestHost' in service,'test signatures must be blocked as tests')
need('lastWebShieldSelfTestInterceptAt' in service,'self test proof missing')
need('WebShieldSelfTestClient' in selftest and 'DatagramSocket' in selftest,'local DNS client missing')
need('check-android-phishing-page' in official and 'AMTSO_ANDROID_PHISHING_TEST' in official,'AMTSO exact path missing')
need('OfficialWebTestIndicators.match' in scanner,'scanner AMTSO support missing')
need('btnWebShieldSelfTest' in layout and 'btnAmtsoWebTest' in layout,'verification controls missing')
need('runWebShieldSelfTest' in main and 'runAmtsoWebTest' in main,'verification actions missing')
need('amtso.org' not in service,'DNS shield must not permanently block whole AMTSO domain')
need('.addRoute(VPN_DNS_ADDRESS, 32)' in service and '.addRoute("0.0.0.0", 0)' not in service,'DNS-only lightweight invariant')
if errors:
    print('WEB_SHIELD_VERIFICATION_3_4_FAILED')
    [print(' - '+e) for e in errors]
    sys.exit(1)
print('WEB_SHIELD_VERIFICATION_3_4_OK local_dns_self_test=1 amtso_exact_link_test=1 permanent_amtso_domain_block=0 test_not_counted_as_threat=1 dns_only=1')
