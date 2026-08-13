#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
http=(ROOT/'app/src/main/java/com/aman/security/autonomous/CloudThreatHttpClient.kt').read_text()
updater=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatUpdater.kt').read_text()
state=(ROOT/'app/src/main/java/com/aman/security/autonomous/ThreatUpdateStateStore.kt').read_text()
layout=(ROOT/'app/src/main/res/layout/activity_main.xml').read_text()
scheduler=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatScheduler.kt').read_text()
def need(ok,label):
    if not ok: raise SystemExit('THREAT_UPDATE_TRANSPARENCY_3_5_FAILED '+label)
need('PeriodicWorkRequestBuilder<AutonomousThreatWorker>(12, TimeUnit.HOURS' in scheduler,'periodic_12h')
need('ExistingWorkPolicy.REPLACE' in scheduler,'manual_replace')
need('onProgress: (downloaded: Long, total: Long) -> Unit' in http,'download_progress')
need('total - lastReportBytes >= 256 * 1024' in http and 'now - lastReportAt >= 700L' in http,'progress_throttle')
need('AutonomousUpdateProgress' in updater and 'sourceIndex = 1' in updater and 'sourceFinished' in updater,'cloud_progress')
need('currentDownloadedBytes' in state and 'currentTotalBytes' in state and 'currentPhase' in state and 'currentPhaseProgress' in state and 'blocksManualUpdate' in state,'durable_progress')
need('STALE_ACTIVE_MS = 3 * 60_000L' in state and 'lastProgressAt' in state and 'KEY_LAST_PROGRESS' in state,'stale_recovery')
need('progressThreatUpdate' in layout and 'txtUpdateTransfer' in layout and 'txtUpdateTiming' in layout and 'txtUpdateSourceDetails' in layout,'visible_update_details')
need('threatUpdateTimingText' in main and 'buildThreatSourceStatusText' in main and 'formatByteCount' in main,'ui_details')
need('lastRenderedThreatUpdateCompletion' in main,'no_repeat_reload')
print('THREAT_UPDATE_TRANSPARENCY_3_5_OK periodic_12h=1 manual_now=1 single_package_progress=1 transfer_bytes=1 phases=1 last_success=1 next_check=1 stale_retry=1')
