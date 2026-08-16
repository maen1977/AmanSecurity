#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def read(path): return (ROOT/path).read_text(encoding='utf-8')
def need(cond,msg):
    if not cond: errors.append(msg)
store=read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatStore.kt')
scanner=read('app/src/main/java/com/aman/security/scanner/UrlScanner.kt')
forwarder=read('app/src/main/java/com/aman/security/web/BrowserForwarder.kt')
builder=read('tools/build_cloud_threat_db.py')
main_tree='\n'.join(p.read_text(encoding='utf-8',errors='ignore') for p in (ROOT/'app/src/main').rglob('*') if p.is_file() and p.stat().st_size<2_000_000)
need('phishing_openphish.sha256' in builder and 'OPENPHISH' in builder,'OpenPhish cloud ingestion missing')
need('url_indicators' in builder and 'url.split("?", 1)[0]' in builder,'query-independent cloud URL hashing missing')
need('CLOUD_OPENPHISH' in store and 'phishOpenPhishIndex.contains' in store,'OpenPhish cloud lookup missing')
need('UrlIndicatorKind.C2_HOST' in store,'C2 pool must be a dedicated kind')
need('FILE_C2' in store,'C2 dedicated file missing')
need('URL_HOST_FILE' in store or 'FILE_MALWARE_URLS' in store,'URL host pool file missing')
need('urlLookupCandidates' in scanner and "url.indexOf('?')" in scanner,'query-independent URL lookup missing')
need('Intent.EXTRA_EXCLUDE_COMPONENTS' in forwarder and 'LinkGuardActivity::class.java' in forwarder,'browser handoff self-loop exclusion missing')
need('queryIntentActivities' not in forwarder,'browser handoff still depends on package visibility pre-query')
need('testsafebrowsing.appspot.com' not in main_tree,'Google test URL must not be hard-coded as a threat')
manifest=read('app/src/main/AndroidManifest.xml')
need('android.accessibilityservice.AccessibilityService' not in manifest and 'BIND_ACCESSIBILITY_SERVICE' not in manifest,'web reputation must not add Accessibility')
if errors:
    print('WEB_REPUTATION_3_5_FAILED'); [print(' - '+e) for e in errors]; sys.exit(1)
print('WEB_REPUTATION_3_5_OK openphish_cloud=1 full_url_hashes=1 queryless_match=1 c2_dedicated_pool=1 browser_handoff_no_prequery=1 google_test_hardcode=0 accessibility=0')
