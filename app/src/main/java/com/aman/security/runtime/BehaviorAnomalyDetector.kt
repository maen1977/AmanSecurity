package com.aman.security.runtime

import android.content.Context
import com.aman.security.protection.ProtectionPreferences

/**
 * On-device behavioral anomaly detector.
 *
 * Global security suites combine signature detection with behavioral
 * anomaly scoring: a rapid cluster of high-risk events (overlay attack,
 * camera/mic access, clipboard theft) inside a short window is the
 * strongest live signal of an active compound attack, even when no
 * single event matches a known signature.
 *
 * Scoring basis: Runtime Shield counter deltas (how many overlay blocks,
 * media alerts and clipboard protections happened recently) combined
 * with the last known timestamps. Fully on-device, no network.
 */
internal class BehaviorAnomalyDetector(private val context: Context) {

    private val preferences = ProtectionPreferences(context)

    /** Evaluate the current behavioral anomaly score (0-100). */
    fun evaluate(): AnomalyVerdict = runCatching {
        if (!preferences.enabled) return@runCatching AnomalyVerdict(score = 0, level = AnomalyLevel.NONE)
        val now = System.currentTimeMillis()
        val overlayActive = isActive(preferences.lastOverlayAlertAt, now)
        val mediaActive = isActive(preferences.lastCameraMicAlertAt, now)
        val clipboardActive = isActive(preferences.lastClipboardProtectAt, now)
        val activeSignals = listOf(overlayActive, mediaActive, clipboardActive).count { it }
        val recencyBoost = recencyScore(now)
        val densityBoost = densityScore(now)
        val score = (activeSignals * SIGNAL_WEIGHT + recencyBoost + densityBoost).coerceAtMost(100)
        val level = when {
            score >= HIGH_THRESHOLD -> AnomalyLevel.HIGH
            score >= REVIEW_THRESHOLD -> AnomalyLevel.REVIEW
            else -> AnomalyLevel.NONE
        }
        AnomalyVerdict(score = score, level = level)
    }.getOrDefault(AnomalyVerdict(score = 0, level = AnomalyLevel.NONE))

    /** Snapshot the raw deltas used for scoring (for UI/test visibility). */
    internal fun deltas(now: Long): AnomalyDeltas = runCatching {
        AnomalyDeltas(
            overlayLastMs = preferences.lastOverlayAlertAt,
            mediaLastMs = preferences.lastCameraMicAlertAt,
            clipboardLastMs = preferences.lastClipboardProtectAt,
            overlayTotal = preferences.totalOverlayAlerts,
            mediaTotal = preferences.totalCameraMicAlerts,
            clipboardTotal = preferences.totalClipboardGuards
        )
    }.getOrDefault(AnomalyDeltas())

    private fun isActive(lastAt: Long, now: Long): Boolean =
        lastAt > 0L && now - lastAt <= SIGNAL_FRESH_MS

    private fun recencyScore(now: Long): Int {
        // Recent activity from several independent channels amplifies risk.
        var score = 0
        if (isActive(preferences.lastOverlayAlertAt, now)) score += RECENT_POINTS
        if (isActive(preferences.lastCameraMicAlertAt, now)) score += RECENT_POINTS
        if (isActive(preferences.lastClipboardProtectAt, now)) score += RECENT_POINTS
        return score
    }

    private fun densityScore(now: Long): Int =
        preferences.totalOverlayAlerts.coerceAtMost((DENSITY_CAP / 2).toLong()).toInt() +
            preferences.totalClipboardGuards.coerceAtMost((DENSITY_CAP / 2).toLong()).toInt()

    companion object {
        private const val SIGNAL_FRESH_MS = 30 * 60_000L
        private const val SIGNAL_WEIGHT = 15
        private const val RECENT_POINTS = 12
        private const val DENSITY_CAP = 24
        private const val HIGH_THRESHOLD = 60
        private const val REVIEW_THRESHOLD = 25
    }
}

internal enum class AnomalyLevel { NONE, REVIEW, HIGH }

internal data class AnomalyVerdict(val score: Int, val level: AnomalyLevel)

internal data class AnomalyDeltas(
    val overlayLastMs: Long = 0L,
    val mediaLastMs: Long = 0L,
    val clipboardLastMs: Long = 0L,
    val overlayTotal: Long = 0L,
    val mediaTotal: Long = 0L,
    val clipboardTotal: Long = 0L
)
