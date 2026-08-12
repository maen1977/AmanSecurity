package com.aman.security.security

enum class SpywareCapabilitySignal {
    ACCESSIBILITY_SERVICE,
    NOTIFICATION_LISTENER,
    DEVICE_ADMIN,
    BOOT_PERSISTENCE,
    OVERLAY_DECLARED,
    SMS_ACCESS,
    CALL_LOG_ACCESS,
    LOCATION_ACCESS,
    MICROPHONE_ACCESS,
    CONTACTS_ACCESS,
    SIDELOADED
}

enum class SpywareReviewLevel {
    LOW,
    REVIEW,
    HIGH
}

data class SpywareRiskAssessment(
    val score: Int,
    val level: SpywareReviewLevel,
    val signals: Set<SpywareCapabilitySignal>
)

/**
 * Stalkerware/spyware capability review policy. Permissions alone never equal malware.
 * Escalation requires combinations of privileged control, surveillance access,
 * persistence and/or confirmed sideloading.
 */
object SpywareRiskPolicy {
    fun evaluate(signals: Set<SpywareCapabilitySignal>): SpywareRiskAssessment {
        val controls = listOf(
            SpywareCapabilitySignal.ACCESSIBILITY_SERVICE,
            SpywareCapabilitySignal.NOTIFICATION_LISTENER,
            SpywareCapabilitySignal.DEVICE_ADMIN
        ).count(signals::contains)
        val surveillance = listOf(
            SpywareCapabilitySignal.SMS_ACCESS,
            SpywareCapabilitySignal.CALL_LOG_ACCESS,
            SpywareCapabilitySignal.LOCATION_ACCESS,
            SpywareCapabilitySignal.MICROPHONE_ACCESS,
            SpywareCapabilitySignal.CONTACTS_ACCESS
        ).count(signals::contains)
        val persistent = SpywareCapabilitySignal.BOOT_PERSISTENCE in signals
        val overlay = SpywareCapabilitySignal.OVERLAY_DECLARED in signals
        val sideloaded = SpywareCapabilitySignal.SIDELOADED in signals

        val sideloadedPrivilegedSurveillance =
            sideloaded && controls >= 1 && surveillance >= 2 && (persistent || overlay)

        var score = controls * 13 + surveillance * 4
        if (persistent) score += 7
        if (overlay) score += 5
        if (sideloaded) score += 10
        // Correlated high-risk capabilities are materially stronger than their isolated signals.
        // Keep the bonus scoped to the same combination that triggers HIGH to avoid inflating
        // ordinary permission-only or single-capability apps.
        if (sideloadedPrivilegedSurveillance) score += 5
        score = score.coerceIn(0, 100)

        val level = when {
            sideloadedPrivilegedSurveillance -> SpywareReviewLevel.HIGH
            controls >= 2 && surveillance >= 3 && persistent -> SpywareReviewLevel.HIGH
            sideloaded && controls >= 1 && surveillance >= 1 -> SpywareReviewLevel.REVIEW
            controls >= 2 && (surveillance >= 2 || persistent) -> SpywareReviewLevel.REVIEW
            else -> SpywareReviewLevel.LOW
        }
        return SpywareRiskAssessment(score, level, signals)
    }
}
