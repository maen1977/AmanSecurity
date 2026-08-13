#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
errors = []

def read(path):
    return (ROOT / path).read_text(encoding='utf-8')

def need(cond, msg):
    if not cond:
        errors.append(msg)

updater = read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatUpdater.kt')
parser = read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatParsers.kt')
store = read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatStore.kt')
scanner = read('app/src/main/java/com/aman/security/scanner/UrlScanner.kt')
forwarder = read('app/src/main/java/com/aman/security/web/BrowserForwarder.kt')
source_policy = read('app/src/main/java/com/aman/security/autonomous/AutonomousSourcePolicy.kt')
main_tree = '\n'.join(
    p.read_text(encoding='utf-8', errors='ignore')
    for p in (ROOT / 'app/src/main').rglob('*')
    if p.is_file() and p.stat().st_size < 2_000_000
)

need('https://openphish.com/feed.txt' in updater, 'OpenPhish live source missing')
need('"openphish.com" -> query == null && path == "/feed.txt"' in source_policy, 'OpenPhish source is not narrowly allowlisted')
need('phishingIndicators' in parser and 'stripQuery' in parser, 'full URL phishing ingestion missing')
need('isRootUrl' in parser, 'host-wide promotion guard missing')
need('kind == UrlIndicatorKind.HOST && c2Index.contains' in store, 'C2 indicators must remain host-only')
need('phishOpenPhishIndex.contains' in store and 'AUTO_OPENPHISH' in store, 'OpenPhish lookup missing')
need('urlLookupCandidates' in scanner and "url.indexOf('?')" in scanner, 'query-independent URL reputation lookup missing')
need('Intent.EXTRA_EXCLUDE_COMPONENTS' in forwarder and 'LinkGuardActivity::class.java' in forwarder, 'browser handoff self-loop exclusion missing')
need('queryIntentActivities' not in forwarder, 'browser handoff still depends on package visibility pre-query')
need('testsafebrowsing.appspot.com' not in main_tree, 'Google test URL must not be hard-coded as a threat')
manifest = read('app/src/main/AndroidManifest.xml')
need('android.accessibilityservice.AccessibilityService' not in manifest and 'BIND_ACCESSIBILITY_SERVICE' not in manifest, 'web reputation patch must not add Accessibility')

if errors:
    print('WEB_REPUTATION_3_4_4_FAILED')
    for error in errors:
        print(' - ' + error)
    sys.exit(1)

print('WEB_REPUTATION_3_4_4_OK openphish_live=1 full_url_hashes=1 queryless_match=1 conservative_host_promotion=1 browser_handoff_no_prequery=1 google_test_hardcode=0 accessibility=0')
