package com.aman.security.autonomous

import android.content.Context

enum class ThreatUpdateState { IDLE, QUEUED, RUNNING, SUCCESS, PARTIAL, FAILED }

data class ThreatUpdateSnapshot(
    val state: ThreatUpdateState,
    val progress: Int,
    val currentSource: String,
    val currentSourceIndex: Int,
    val totalSources: Int,
    val completedSources: Int,
    val currentPhase: AutonomousUpdatePhase,
    val currentPhaseProgress: Int,
    val currentDownloadedBytes: Long,
    val currentTotalBytes: Long,
    val startedAt: Long,
    val lastProgressAt: Long,
    val finishedAt: Long,
    val successfulSources: Int,
    val failedSources: Int,
    val changedSources: Int,
    val malwareHashes: Int,
    val phishingHosts: Int,
    val c2Hosts: Int,
    val androidCves: Int,
    val error: String
) {
    val isActive: Boolean get() = state == ThreatUpdateState.QUEUED || state == ThreatUpdateState.RUNNING
    val isStaleActive: Boolean get() {
        val heartbeat = lastProgressAt.takeIf { it > 0L } ?: startedAt
        return isActive && heartbeat > 0L && System.currentTimeMillis() - heartbeat >= STALE_ACTIVE_MS
    }
    val blocksManualUpdate: Boolean get() = isActive && !isStaleActive

    companion object {
        private const val STALE_ACTIVE_MS = 3 * 60_000L
    }
}

/** Durable UI/runtime state for both manual and periodic threat-intelligence updates. */
class ThreatUpdateStateStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun queued() {
        val now = System.currentTimeMillis()
        prefs.edit()
            .putString(KEY_STATE, ThreatUpdateState.QUEUED.name)
            .putInt(KEY_PROGRESS, 0)
            .putString(KEY_SOURCE, "queued")
            .putInt(KEY_SOURCE_INDEX, 0)
            .putInt(KEY_TOTAL_SOURCES, AutonomousThreatUpdater.TOTAL_SOURCES)
            .putInt(KEY_COMPLETED_SOURCES, 0)
            .putString(KEY_PHASE, AutonomousUpdatePhase.CONNECTING.name)
            .putInt(KEY_PHASE_PROGRESS, 0)
            .putLong(KEY_DOWNLOADED_BYTES, 0L)
            .putLong(KEY_TOTAL_BYTES, -1L)
            .putLong(KEY_STARTED, now)
            .putLong(KEY_LAST_PROGRESS, now)
            .putLong(KEY_FINISHED, 0L)
            .putInt(KEY_SUCCESSFUL, 0)
            .putInt(KEY_FAILED, 0)
            .putInt(KEY_CHANGED, 0)
            .putString(KEY_ERROR, "")
            .apply()
    }

    fun running() {
        val previous = snapshot()
        val now = System.currentTimeMillis()
        val queuedRecently = previous.state == ThreatUpdateState.QUEUED &&
            previous.startedAt > 0L && now - previous.startedAt < 30 * 60_000L
        prefs.edit()
            .putString(KEY_STATE, ThreatUpdateState.RUNNING.name)
            .putInt(KEY_PROGRESS, 1)
            .putString(KEY_SOURCE, "starting")
            .putInt(KEY_SOURCE_INDEX, 0)
            .putInt(KEY_TOTAL_SOURCES, AutonomousThreatUpdater.TOTAL_SOURCES)
            .putInt(KEY_COMPLETED_SOURCES, 0)
            .putString(KEY_PHASE, AutonomousUpdatePhase.CONNECTING.name)
            .putInt(KEY_PHASE_PROGRESS, 0)
            .putLong(KEY_DOWNLOADED_BYTES, 0L)
            .putLong(KEY_TOTAL_BYTES, -1L)
            .putLong(KEY_STARTED, if (queuedRecently) previous.startedAt else now)
            .putLong(KEY_LAST_PROGRESS, now)
            .putLong(KEY_FINISHED, 0L)
            .putInt(KEY_SUCCESSFUL, 0)
            .putInt(KEY_FAILED, 0)
            .putInt(KEY_CHANGED, 0)
            .putString(KEY_ERROR, "")
            .apply()
    }

    /** Persist fine-grained source/download progress without allowing the visible percent to move backwards. */
    fun progress(update: AutonomousUpdateProgress) {
        val current = snapshot()
        val totalSources = update.totalSources.coerceAtLeast(1)
        val completed = update.completedSources.coerceIn(0, totalSources)
        val sourceIndex = update.sourceIndex.coerceIn(1, totalSources)
        val phaseProgress = update.phaseProgress.coerceIn(0, 100) / 100.0
        val fraction = when {
            update.sourceFinished -> 1.0
            update.phase == AutonomousUpdatePhase.CONNECTING -> 0.03
            update.phase == AutonomousUpdatePhase.DOWNLOADING && update.totalBytes > 0L ->
                0.05 + (update.downloadedBytes.toDouble() / update.totalBytes.toDouble()).coerceIn(0.0, 1.0) * 0.50
            update.phase == AutonomousUpdatePhase.DOWNLOADING -> 0.08
            update.phase == AutonomousUpdatePhase.PARSING -> 0.58 + phaseProgress * 0.20
            update.phase == AutonomousUpdatePhase.INDEXING -> 0.80 + phaseProgress * 0.13
            update.phase == AutonomousUpdatePhase.APPLYING -> 0.94 + phaseProgress * 0.05
            else -> 0.03
        }
        val base = (sourceIndex - 1).coerceAtLeast(0).toDouble()
        val computed = (((base + fraction) / totalSources.toDouble()) * 100.0).toInt().coerceIn(1, 99)
        val percent = maxOf(current.progress, computed, if (update.sourceFinished) (completed * 100 / totalSources).coerceAtMost(99) else 1)

        val editor = prefs.edit()
            .putString(KEY_STATE, ThreatUpdateState.RUNNING.name)
            .putInt(KEY_PROGRESS, percent)
            .putString(KEY_SOURCE, update.sourceKey.take(80))
            .putInt(KEY_SOURCE_INDEX, sourceIndex)
            .putInt(KEY_TOTAL_SOURCES, totalSources)
            .putInt(KEY_COMPLETED_SOURCES, completed)
            .putString(KEY_PHASE, update.phase.name)
            .putInt(KEY_PHASE_PROGRESS, update.phaseProgress.coerceIn(0, 100))
            .putLong(KEY_DOWNLOADED_BYTES, update.downloadedBytes.coerceAtLeast(0L))
            .putLong(KEY_TOTAL_BYTES, update.totalBytes)
            .putLong(KEY_LAST_PROGRESS, System.currentTimeMillis())
        if (update.sourceFinished && update.sourceSucceeded != null) {
            val success = current.successfulSources + if (update.sourceSucceeded) 1 else 0
            val failed = current.failedSources + if (!update.sourceSucceeded) 1 else 0
            editor.putInt(KEY_SUCCESSFUL, success.coerceAtMost(totalSources))
            editor.putInt(KEY_FAILED, failed.coerceAtMost(totalSources))
        }
        editor.apply()
    }

    fun complete(result: AutonomousUpdateResult) {
        val now = System.currentTimeMillis()
        when (result) {
            is AutonomousUpdateResult.Success -> writeTerminal(
                state = ThreatUpdateState.SUCCESS,
                successful = result.info.successfulSourcesLastRun,
                failed = result.info.failedSourcesLastRun,
                changed = result.changedSources,
                malware = result.info.malwareFileHashes,
                phishing = result.info.phishingHosts,
                c2 = result.info.c2Hosts,
                cves = result.info.androidCveCount,
                now = now,
                error = ""
            )
            is AutonomousUpdateResult.Partial -> writeTerminal(
                state = ThreatUpdateState.PARTIAL,
                successful = result.successfulSources,
                failed = result.failedSources,
                changed = result.changedSources,
                malware = result.info.malwareFileHashes,
                phishing = result.info.phishingHosts,
                c2 = result.info.c2Hosts,
                cves = result.info.androidCveCount,
                now = now,
                error = ""
            )
            AutonomousUpdateResult.NoSourceAvailable -> writeTerminal(
                state = ThreatUpdateState.FAILED,
                successful = 0,
                failed = AutonomousThreatUpdater.TOTAL_SOURCES,
                changed = 0,
                malware = 0,
                phishing = 0,
                c2 = 0,
                cves = 0,
                now = now,
                error = "no_source_available"
            )
        }
    }

    fun fail(message: String) {
        val current = snapshot()
        writeTerminal(
            state = ThreatUpdateState.FAILED,
            successful = current.successfulSources,
            failed = current.failedSources.coerceAtLeast(1),
            changed = current.changedSources,
            malware = current.malwareHashes,
            phishing = current.phishingHosts,
            c2 = current.c2Hosts,
            cves = current.androidCves,
            now = System.currentTimeMillis(),
            error = message.take(240)
        )
    }

    private fun writeTerminal(
        state: ThreatUpdateState,
        successful: Int,
        failed: Int,
        changed: Int,
        malware: Int,
        phishing: Int,
        c2: Int,
        cves: Int,
        now: Long,
        error: String
    ) {
        prefs.edit()
            .putString(KEY_STATE, state.name)
            .putInt(KEY_PROGRESS, 100)
            .putString(KEY_SOURCE, "complete")
            .putInt(KEY_SOURCE_INDEX, AutonomousThreatUpdater.TOTAL_SOURCES)
            .putInt(KEY_TOTAL_SOURCES, AutonomousThreatUpdater.TOTAL_SOURCES)
            .putInt(KEY_COMPLETED_SOURCES, AutonomousThreatUpdater.TOTAL_SOURCES)
            .putString(KEY_PHASE, AutonomousUpdatePhase.APPLYING.name)
            .putInt(KEY_PHASE_PROGRESS, 100)
            .putLong(KEY_DOWNLOADED_BYTES, 0L)
            .putLong(KEY_TOTAL_BYTES, -1L)
            .putLong(KEY_LAST_PROGRESS, now)
            .putLong(KEY_FINISHED, now)
            .putInt(KEY_SUCCESSFUL, successful.coerceAtLeast(0))
            .putInt(KEY_FAILED, failed.coerceAtLeast(0))
            .putInt(KEY_CHANGED, changed.coerceAtLeast(0))
            .putInt(KEY_MALWARE, malware.coerceAtLeast(0))
            .putInt(KEY_PHISHING, phishing.coerceAtLeast(0))
            .putInt(KEY_C2, c2.coerceAtLeast(0))
            .putInt(KEY_CVES, cves.coerceAtLeast(0))
            .putString(KEY_ERROR, error)
            .apply()
    }

    fun snapshot(): ThreatUpdateSnapshot {
        val state = runCatching { ThreatUpdateState.valueOf(prefs.getString(KEY_STATE, ThreatUpdateState.IDLE.name)!!) }
            .getOrDefault(ThreatUpdateState.IDLE)
        return ThreatUpdateSnapshot(
            state = state,
            progress = prefs.getInt(KEY_PROGRESS, 0).coerceIn(0, 100),
            currentSource = prefs.getString(KEY_SOURCE, "").orEmpty(),
            currentSourceIndex = prefs.getInt(KEY_SOURCE_INDEX, 0),
            totalSources = prefs.getInt(KEY_TOTAL_SOURCES, AutonomousThreatUpdater.TOTAL_SOURCES).coerceAtLeast(1),
            completedSources = prefs.getInt(KEY_COMPLETED_SOURCES, 0).coerceAtLeast(0),
            currentPhase = runCatching { AutonomousUpdatePhase.valueOf(prefs.getString(KEY_PHASE, AutonomousUpdatePhase.CONNECTING.name)!!) }.getOrDefault(AutonomousUpdatePhase.CONNECTING),
            currentPhaseProgress = prefs.getInt(KEY_PHASE_PROGRESS, 0).coerceIn(0, 100),
            currentDownloadedBytes = prefs.getLong(KEY_DOWNLOADED_BYTES, 0L).coerceAtLeast(0L),
            currentTotalBytes = prefs.getLong(KEY_TOTAL_BYTES, -1L),
            startedAt = prefs.getLong(KEY_STARTED, 0L),
            lastProgressAt = prefs.getLong(KEY_LAST_PROGRESS, prefs.getLong(KEY_STARTED, 0L)),
            finishedAt = prefs.getLong(KEY_FINISHED, 0L),
            successfulSources = prefs.getInt(KEY_SUCCESSFUL, 0),
            failedSources = prefs.getInt(KEY_FAILED, 0),
            changedSources = prefs.getInt(KEY_CHANGED, 0),
            malwareHashes = prefs.getInt(KEY_MALWARE, 0),
            phishingHosts = prefs.getInt(KEY_PHISHING, 0),
            c2Hosts = prefs.getInt(KEY_C2, 0),
            androidCves = prefs.getInt(KEY_CVES, 0),
            error = prefs.getString(KEY_ERROR, "").orEmpty()
        )
    }

    companion object {
        private const val PREFS = "aman_threat_update_state_v2"
        private const val KEY_STATE = "state"
        private const val KEY_PROGRESS = "progress"
        private const val KEY_SOURCE = "source"
        private const val KEY_SOURCE_INDEX = "source_index"
        private const val KEY_TOTAL_SOURCES = "total_sources"
        private const val KEY_COMPLETED_SOURCES = "completed_sources"
        private const val KEY_PHASE = "phase"
        private const val KEY_PHASE_PROGRESS = "phase_progress"
        private const val KEY_DOWNLOADED_BYTES = "downloaded_bytes"
        private const val KEY_TOTAL_BYTES = "total_bytes"
        private const val KEY_STARTED = "started"
        private const val KEY_LAST_PROGRESS = "last_progress"
        private const val KEY_FINISHED = "finished"
        private const val KEY_SUCCESSFUL = "successful"
        private const val KEY_FAILED = "failed"
        private const val KEY_CHANGED = "changed"
        private const val KEY_MALWARE = "malware"
        private const val KEY_PHISHING = "phishing"
        private const val KEY_C2 = "c2"
        private const val KEY_CVES = "cves"
        private const val KEY_ERROR = "error"
    }
}
