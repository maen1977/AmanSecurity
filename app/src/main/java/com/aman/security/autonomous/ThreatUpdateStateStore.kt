package com.aman.security.autonomous

import android.content.Context

enum class ThreatUpdateState { IDLE, QUEUED, RUNNING, SUCCESS, PARTIAL, FAILED }

data class ThreatUpdateSnapshot(
    val state: ThreatUpdateState,
    val progress: Int,
    val currentSource: String,
    val startedAt: Long,
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
            .putLong(KEY_STARTED, now)
            .putLong(KEY_FINISHED, 0L)
            .putString(KEY_ERROR, "")
            .apply()
    }

    fun running() {
        prefs.edit()
            .putString(KEY_STATE, ThreatUpdateState.RUNNING.name)
            .putInt(KEY_PROGRESS, 1)
            .putString(KEY_SOURCE, "starting")
            .putLong(KEY_STARTED, System.currentTimeMillis())
            .putLong(KEY_FINISHED, 0L)
            .putString(KEY_ERROR, "")
            .apply()
    }

    fun progress(source: String, completed: Int, total: Int) {
        val percent = if (total <= 0) 1 else ((completed.coerceIn(0, total) * 95) / total).coerceIn(1, 95)
        prefs.edit()
            .putString(KEY_STATE, ThreatUpdateState.RUNNING.name)
            .putInt(KEY_PROGRESS, percent)
            .putString(KEY_SOURCE, source.take(80))
            .apply()
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
            failed = current.failedSources,
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
            startedAt = prefs.getLong(KEY_STARTED, 0L),
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
        private const val PREFS = "aman_threat_update_state_v1"
        private const val KEY_STATE = "state"
        private const val KEY_PROGRESS = "progress"
        private const val KEY_SOURCE = "source"
        private const val KEY_STARTED = "started"
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
