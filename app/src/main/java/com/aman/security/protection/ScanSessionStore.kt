package com.aman.security.protection

import android.content.Context
import java.util.UUID

enum class PersistentScanMode { QUICK, SMART, FULL }
enum class PersistentScanState { IDLE, QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED }

data class ScanSessionSnapshot(
    val sessionId: String,
    val mode: PersistentScanMode,
    val state: PersistentScanState,
    val progress: Int,
    val stage: String,
    val target: String,
    val scope: String,
    val startedAt: Long,
    val updatedAt: Long,
    val completedAt: Long,
    val scannedApps: Int,
    val reviewApps: Int,
    val highRiskApps: Int,
    val knownThreats: Int,
    val scannedFiles: Int,
    val fileAlerts: Int,
    val securityWarnings: Int,
    val securityHighs: Int,
    val spywareReview: Int,
    val spywareHigh: Int,
    val cancelledRequested: Boolean,
    val error: String
) {
    val isActive: Boolean get() = state == PersistentScanState.QUEUED || state == PersistentScanState.RUNNING
    /** Confirmed virus/file/device threats only. Heuristic app risk is a review, not proof of malware. */
    val totalAlerts: Int get() = knownThreats + fileAlerts + securityHighs
    val totalAttention: Int get() = reviewApps + highRiskApps + securityWarnings + spywareReview + spywareHigh
}

/**
 * Durable scan state that is independent from MainActivity. The foreground protection service
 * owns the actual scan; the UI only renders this snapshot. This is intentionally tiny and uses
 * SharedPreferences so reopening the app never makes an active/completed scan disappear.
 */
class ScanSessionStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    @Synchronized
    fun begin(mode: PersistentScanMode): ScanSessionSnapshot {
        val current = snapshot()
        if (current.isActive) return current
        val now = System.currentTimeMillis()
        val id = UUID.randomUUID().toString()
        prefs.edit()
            .putString(KEY_ID, id)
            .putString(KEY_MODE, mode.name)
            .putString(KEY_STATE, PersistentScanState.QUEUED.name)
            .putInt(KEY_PROGRESS, 0)
            .putString(KEY_STAGE, "preparing")
            .putString(KEY_TARGET, "")
            .putString(KEY_SCOPE, "")
            .putLong(KEY_STARTED, now)
            .putLong(KEY_UPDATED, now)
            .putLong(KEY_COMPLETED, 0L)
            .putInt(KEY_SCANNED_APPS, 0)
            .putInt(KEY_REVIEW_APPS, 0)
            .putInt(KEY_HIGH_APPS, 0)
            .putInt(KEY_KNOWN, 0)
            .putInt(KEY_SCANNED_FILES, 0)
            .putInt(KEY_FILE_ALERTS, 0)
            .putInt(KEY_SECURITY_WARNINGS, 0)
            .putInt(KEY_SECURITY_HIGHS, 0)
            .putInt(KEY_SPYWARE_REVIEW, 0)
            .putInt(KEY_SPYWARE_HIGH, 0)
            .putBoolean(KEY_CANCEL_REQUESTED, false)
            .putString(KEY_ERROR, "")
            .commit()
        return snapshot()
    }

    @Synchronized
    fun markRunning(sessionId: String) {
        if (!matches(sessionId)) return
        prefs.edit()
            .putString(KEY_STATE, PersistentScanState.RUNNING.name)
            .putLong(KEY_UPDATED, System.currentTimeMillis())
            .apply()
    }

    @Synchronized
    fun updateProgress(sessionId: String, progress: Int, stage: String, target: String = "", scope: String = "") {
        if (!matches(sessionId)) return
        prefs.edit()
            .putString(KEY_STATE, PersistentScanState.RUNNING.name)
            .putInt(KEY_PROGRESS, progress.coerceIn(0, 99))
            .putString(KEY_STAGE, stage.take(48))
            .putString(KEY_TARGET, target.take(240))
            .putString(KEY_SCOPE, scope.take(320))
            .putLong(KEY_UPDATED, System.currentTimeMillis())
            .apply()
    }

    @Synchronized
    fun complete(
        sessionId: String,
        scannedApps: Int,
        reviewApps: Int,
        highRiskApps: Int,
        knownThreats: Int,
        scannedFiles: Int,
        fileAlerts: Int,
        securityWarnings: Int,
        securityHighs: Int,
        spywareReview: Int,
        spywareHigh: Int
    ) {
        if (!matches(sessionId)) return
        val now = System.currentTimeMillis()
        prefs.edit()
            .putString(KEY_STATE, PersistentScanState.COMPLETED.name)
            .putInt(KEY_PROGRESS, 100)
            .putString(KEY_STAGE, "complete")
            .putLong(KEY_UPDATED, now)
            .putLong(KEY_COMPLETED, now)
            .putInt(KEY_SCANNED_APPS, scannedApps.coerceAtLeast(0))
            .putInt(KEY_REVIEW_APPS, reviewApps.coerceAtLeast(0))
            .putInt(KEY_HIGH_APPS, highRiskApps.coerceAtLeast(0))
            .putInt(KEY_KNOWN, knownThreats.coerceAtLeast(0))
            .putInt(KEY_SCANNED_FILES, scannedFiles.coerceAtLeast(0))
            .putInt(KEY_FILE_ALERTS, fileAlerts.coerceAtLeast(0))
            .putInt(KEY_SECURITY_WARNINGS, securityWarnings.coerceAtLeast(0))
            .putInt(KEY_SECURITY_HIGHS, securityHighs.coerceAtLeast(0))
            .putInt(KEY_SPYWARE_REVIEW, spywareReview.coerceAtLeast(0))
            .putInt(KEY_SPYWARE_HIGH, spywareHigh.coerceAtLeast(0))
            .putBoolean(KEY_CANCEL_REQUESTED, false)
            .putString(KEY_ERROR, "")
            .commit()
    }

    @Synchronized
    fun fail(sessionId: String, message: String) {
        if (!matches(sessionId)) return
        val now = System.currentTimeMillis()
        prefs.edit()
            .putString(KEY_STATE, PersistentScanState.FAILED.name)
            .putLong(KEY_UPDATED, now)
            .putLong(KEY_COMPLETED, now)
            .putBoolean(KEY_CANCEL_REQUESTED, false)
            .putString(KEY_ERROR, message.take(300))
            .commit()
    }

    @Synchronized
    fun requestCancel(sessionId: String) {
        if (!matches(sessionId)) return
        prefs.edit().putBoolean(KEY_CANCEL_REQUESTED, true).putLong(KEY_UPDATED, System.currentTimeMillis()).apply()
    }

    @Synchronized
    fun cancel(sessionId: String) {
        if (!matches(sessionId)) return
        val now = System.currentTimeMillis()
        prefs.edit()
            .putString(KEY_STATE, PersistentScanState.CANCELLED.name)
            .putLong(KEY_UPDATED, now)
            .putLong(KEY_COMPLETED, now)
            .putBoolean(KEY_CANCEL_REQUESTED, false)
            .commit()
    }

    fun isCancelRequested(sessionId: String): Boolean = matches(sessionId) && prefs.getBoolean(KEY_CANCEL_REQUESTED, false)

    fun snapshot(): ScanSessionSnapshot {
        val mode = runCatching { PersistentScanMode.valueOf(prefs.getString(KEY_MODE, PersistentScanMode.QUICK.name)!!) }
            .getOrDefault(PersistentScanMode.QUICK)
        val state = runCatching { PersistentScanState.valueOf(prefs.getString(KEY_STATE, PersistentScanState.IDLE.name)!!) }
            .getOrDefault(PersistentScanState.IDLE)
        return ScanSessionSnapshot(
            sessionId = prefs.getString(KEY_ID, "").orEmpty(),
            mode = mode,
            state = state,
            progress = prefs.getInt(KEY_PROGRESS, 0).coerceIn(0, 100),
            stage = prefs.getString(KEY_STAGE, "").orEmpty(),
            target = prefs.getString(KEY_TARGET, "").orEmpty(),
            scope = prefs.getString(KEY_SCOPE, "").orEmpty(),
            startedAt = prefs.getLong(KEY_STARTED, 0L),
            updatedAt = prefs.getLong(KEY_UPDATED, 0L),
            completedAt = prefs.getLong(KEY_COMPLETED, 0L),
            scannedApps = prefs.getInt(KEY_SCANNED_APPS, 0),
            reviewApps = prefs.getInt(KEY_REVIEW_APPS, 0),
            highRiskApps = prefs.getInt(KEY_HIGH_APPS, 0),
            knownThreats = prefs.getInt(KEY_KNOWN, 0),
            scannedFiles = prefs.getInt(KEY_SCANNED_FILES, 0),
            fileAlerts = prefs.getInt(KEY_FILE_ALERTS, 0),
            securityWarnings = prefs.getInt(KEY_SECURITY_WARNINGS, 0),
            securityHighs = prefs.getInt(KEY_SECURITY_HIGHS, 0),
            spywareReview = prefs.getInt(KEY_SPYWARE_REVIEW, 0),
            spywareHigh = prefs.getInt(KEY_SPYWARE_HIGH, 0),
            cancelledRequested = prefs.getBoolean(KEY_CANCEL_REQUESTED, false),
            error = prefs.getString(KEY_ERROR, "").orEmpty()
        )
    }

    private fun matches(sessionId: String): Boolean = sessionId.isNotBlank() && prefs.getString(KEY_ID, "") == sessionId

    companion object {
        private const val PREFS = "aman_scan_session_v1"
        private const val KEY_ID = "id"
        private const val KEY_MODE = "mode"
        private const val KEY_STATE = "state"
        private const val KEY_PROGRESS = "progress"
        private const val KEY_STAGE = "stage"
        private const val KEY_TARGET = "target"
        private const val KEY_SCOPE = "scope"
        private const val KEY_STARTED = "started"
        private const val KEY_UPDATED = "updated"
        private const val KEY_COMPLETED = "completed"
        private const val KEY_SCANNED_APPS = "scanned_apps"
        private const val KEY_REVIEW_APPS = "review_apps"
        private const val KEY_HIGH_APPS = "high_apps"
        private const val KEY_KNOWN = "known"
        private const val KEY_SCANNED_FILES = "scanned_files"
        private const val KEY_FILE_ALERTS = "file_alerts"
        private const val KEY_SECURITY_WARNINGS = "security_warnings"
        private const val KEY_SECURITY_HIGHS = "security_highs"
        private const val KEY_SPYWARE_REVIEW = "spyware_review"
        private const val KEY_SPYWARE_HIGH = "spyware_high"
        private const val KEY_CANCEL_REQUESTED = "cancel_requested"
        private const val KEY_ERROR = "error"
    }
}
