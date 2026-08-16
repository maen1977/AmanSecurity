package com.aman.security.runtime

import android.content.Context
import com.aman.security.protection.ProtectionPreferences

/**
 * Live protection coordinator: unifies every runtime guard into a single
 * on-device protection score (0-100), exactly how global mobile security
 * suites present a "protection readiness" posture to the user.
 *
 * Score basis (all local, no network):
 * - Runtime guard health (overlay / camera-mic / clipboard / hardening enabled)
 * - System hardening audit grade
 * - Behavioral anomaly state (compound-attack likelihood)
 * - Privacy exposure state
 */
internal class RuntimeShieldCoordinator(private val context: Context) {

    private val preferences = ProtectionPreferences(context)

    fun protectionScore(): ProtectionScoreReport = runCatching {
        val hardening = SystemHardeningAuditor(context).audit()
        val anomaly = BehaviorAnomalyDetector(context).evaluate()
        val exposure = PrivacyExposureAssessor(context).evaluate()

        val healthScore = guardHealthScore()
        val hardeningScore = if (hardening.isHardened) HARDENING_FULL_POINTS else (hardening.score * HARDENING_SCALE).toInt()
        val anomalyPenalty = when (anomaly.level) {
            AnomalyLevel.HIGH -> ANOMALY_HIGH_PENALTY
            AnomalyLevel.REVIEW -> ANOMALY_REVIEW_PENALTY
            AnomalyLevel.NONE -> 0
        }
        val exposurePenalty = when (exposure.level) {
            ExposureLevel.HIGH -> EXPOSURE_HIGH_PENALTY
            ExposureLevel.REVIEW -> EXPOSURE_REVIEW_PENALTY
            ExposureLevel.NONE -> 0
        }
        val score = (healthScore + hardeningScore - anomalyPenalty - exposurePenalty).toInt()
            .coerceIn(0, 100)
        ProtectionScoreReport(
            score = score,
            anomalyLevel = anomaly.level,
            exposureLevel = exposure.level,
            hardeningGrade = if (hardening.isHardened) HardeningGrade.FULL else HardeningGrade.PARTIAL
        )
    }.getOrDefault(
        ProtectionScoreReport(score = 0, anomalyLevel = AnomalyLevel.NONE, exposureLevel = ExposureLevel.NONE, hardeningGrade = HardeningGrade.PARTIAL)
    )

    private fun guardHealthScore(): Int {
        var points = 0
        if (preferences.overlayGuardEnabled) points += GUARD_POINTS
        if (preferences.cameraMicGuardEnabled) points += GUARD_POINTS
        if (preferences.clipboardGuardEnabled) points += GUARD_POINTS
        if (preferences.foregroundAppScannerEnabled) points += GUARD_POINTS
        return points
    }

    companion object {
        private const val GUARD_POINTS = 15
        private const val HARDENING_FULL_POINTS = 40
        private const val HARDENING_SCALE = 0.4
        private const val ANOMALY_HIGH_PENALTY = 30
        private const val ANOMALY_REVIEW_PENALTY = 12
        private const val EXPOSURE_HIGH_PENALTY = 20
        private const val EXPOSURE_REVIEW_PENALTY = 8
        internal const val STRONG_THRESHOLD = 85
        internal const val REVIEW_THRESHOLD = 60
    }
}

internal enum class HardeningGrade { FULL, PARTIAL }

internal data class ProtectionScoreReport(
    val score: Int,
    val anomalyLevel: AnomalyLevel,
    val exposureLevel: ExposureLevel,
    val hardeningGrade: HardeningGrade
)
