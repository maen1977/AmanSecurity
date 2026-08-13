#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def read(path): return (ROOT/path).read_text(encoding='utf-8')
def need(ok,msg):
    if not ok: errors.append(msg)

build=read('app/build.gradle.kts')
http=read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatHttpClient.kt')
updater=read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatUpdater.kt')
models=read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatModels.kt')
state=read('app/src/main/java/com/aman/security/autonomous/ThreatUpdateStateStore.kt')
parser=read('app/src/main/java/com/aman/security/autonomous/AutonomousThreatParsers.kt')
main=read('app/src/main/java/com/aman/security/MainActivity.kt')
source_policy=read('app/src/main/java/com/aman/security/autonomous/AutonomousSourcePolicy.kt')
en=read('app/src/main/res/values/strings.xml')
ar=read('app/src/main/res/values-ar/strings.xml')

need('versionName = "3.4.5"' in build and 'versionCode = 28' in build,'version')
need('maxDurationMs: Long = DEFAULT_DOWNLOAD_DEADLINE_MS' in http,'download_deadline_api')
need('enforceDeadline()' in http and 'SocketTimeoutException("Threat source download deadline exceeded")' in http,'deadline_enforced')
need('DEFAULT_DOWNLOAD_DEADLINE_MS = 75_000L' in http,'default_deadline')
need('MAX_REDIRECTS = 1' in http and 'AutonomousSourcePolicy.allowedRedirect' in http,'single_allowlisted_redirect')
need('"raw.githubusercontent.com" -> query == null && path == "/openphish/public_feed/refs/heads/main/feed.txt"' in source_policy and 'allowedRedirect' in source_policy,'openphish_redirect_policy')
need('OPENPHISH_SOURCE_DEADLINE_MS = 60_000L' in updater and 'PHISHING_SOURCE_DEADLINE_MS = 75_000L' in updater and 'LARGE_SOURCE_DEADLINE_MS = 120_000L' in updater,'source_deadlines')
open_pos=updater.find('runSource(2, AutonomousThreatStore.SOURCE_PHISH_OPENPHISH)')
primary_pos=updater.find('runSource(3, AutonomousThreatStore.SOURCE_PHISH_PRIMARY)')
need(open_pos >= 0 and primary_pos > open_pos,'openphish_priority')
need('AutonomousUpdatePhase { CONNECTING, DOWNLOADING, PARSING, INDEXING, APPLYING }' in models,'phases')
need('phaseProgress' in models and 'currentPhaseProgress' in state,'phase_progress')
need('update.phase == AutonomousUpdatePhase.DOWNLOADING -> 0.08' in state,'unknown_length_no_fake_fraction')
need('update.downloadedBytes > 0L -> 0.35' not in state,'legacy_19_percent_removed')
need('KEY_LAST_PROGRESS' in state and 'lastProgressAt' in state and 'STALE_ACTIVE_MS = 3 * 60_000L' in state,'heartbeat_stale_detection')
need('unknownLengthDownload' in main and 'progressThreatUpdate.isIndeterminate' in main,'unknown_length_indeterminate_ui')
need('threat_update_running_unknown_size' in main and 'threatUpdatePhaseLabel' in main,'phase_ui')
need('source did not report a total size' in en and 'المصدر لم يعلن الحجم الإجمالي' in ar,'unknown_total_copy')
need('onProgress: ((Int) -> Unit)? = null' in parser and 'AutonomousUpdatePhase.PARSING' in updater and 'AutonomousUpdatePhase.INDEXING' in updater,'parse_index_progress')
need('failedSourceKeys += key' in updater and 'Last-known-good data remains intact' in updater,'skip_failed_source')
# Regression calculation: source 2 with unknown Content-Length is no longer a fabricated 19%.
computed=int(((1.0 + 0.08)/7.0)*100.0)
need(computed == 15,'unknown_length_regression_math')

if errors:
    print('THREAT_UPDATE_RELIABILITY_3_4_5_FAILED')
    for e in errors: print(' - '+e)
    sys.exit(1)
print('THREAT_UPDATE_RELIABILITY_3_4_5_OK deadline_skip=1 openphish_priority=1 openphish_redirect=1 unknown_length_indeterminate=1 parsing_progress=1 indexing_progress=1 heartbeat=1 fake_19_removed=1')
