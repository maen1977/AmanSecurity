package com.aman.security.security

enum class SpywareCapabilitySignal {
    ACCESSIBILITY_SERVICE,
    ACCESSIBILITY_ACTIVE,
    NOTIFICATION_LISTENER,
    NOTIFICATION_LISTENER_ACTIVE,
    DEVICE_ADMIN,
    DEVICE_ADMIN_ACTIVE,
    BOOT_PERSISTENCE,
    OVERLAY_DECLARED,
    SMS_ACCESS,
    CALL_LOG_ACCESS,
    LOCATION_ACCESS,
    MICROPHONE_ACCESS,
    CONTACTS_ACCESS,
    CAMERA_ACCESS,
    PHONE_STATE_ACCESS,
    INPUT_METHOD_SERVICE,
    AUDIO_RECORDING_SERVICE,
    STORAGE_PERMISSION,
    QUERY_ALL_PACKAGES,
    READ_MEDIA_ACCESS,
    CAMERA_MIC_COMBO,
    SURVEILLANCE_COMBO,
    SENSITIVE_PERMISSION_CLUSTER,
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
        val declaredControls = listOf(
            SpywareCapabilitySignal.ACCESSIBILITY_SERVICE,
            SpywareCapabilitySignal.NOTIFICATION_LISTENER,
            SpywareCapabilitySignal.DEVICE_ADMIN
        ).count(signals::contains)
        val activeControls = listOf(
            SpywareCapabilitySignal.ACCESSIBILITY_ACTIVE,
            SpywareCapabilitySignal.NOTIFICATION_LISTENER_ACTIVE,
            SpywareCapabilitySignal.DEVICE_ADMIN_ACTIVE
        ).count(signals::contains)
        val controls = declaredControls
        val hasActiveControl = activeControls > 0
        val surveillance = listOf(
            SpywareCapabilitySignal.SMS_ACCESS,
            SpywareCapabilitySignal.CALL_LOG_ACCESS,
            SpywareCapabilitySignal.LOCATION_ACCESS,
            SpywareCapabilitySignal.MICROPHONE_ACCESS,
            SpywareCapabilitySignal.CONTACTS_ACCESS,
            SpywareCapabilitySignal.CAMERA_ACCESS,
            SpywareCapabilitySignal.PHONE_STATE_ACCESS,
            SpywareCapabilitySignal.INPUT_METHOD_SERVICE,
            SpywareCapabilitySignal.AUDIO_RECORDING_SERVICE,
            SpywareCapabilitySignal.READ_MEDIA_ACCESS
        ).count(signals::contains)
        val persistent = SpywareCapabilitySignal.BOOT_PERSISTENCE in signals
        val overlay = SpywareCapabilitySignal.OVERLAY_DECLARED in signals
        val sideloaded = SpywareCapabilitySignal.SIDELOADED in signals
        val clustered = SpywareCapabilitySignal.SENSITIVE_PERMISSION_CLUSTER in signals

        var score = controls * 13 + activeControls * 6 + surveillance * 4
        if (clustered) score += 8
        if (persistent) score += 7
        if (overlay) score += 5
        if (sideloaded) score += 10
        if (sideloaded && clustered) score += 12
        if (SpywareCapabilitySignal.INPUT_METHOD_SERVICE in signals) score += 7
        if (SpywareCapabilitySignal.AUDIO_RECORDING_SERVICE in signals) score += 5
        if (SpywareCapabilitySignal.CAMERA_MIC_COMBO in signals) score += 8
        if (SpywareCapabilitySignal.SURVEILLANCE_COMBO in signals) score += 10
        if (SpywareCapabilitySignal.QUERY_ALL_PACKAGES in signals && (surveillance >= 2 || controls >= 1)) score += 6

        val level = when {
            sideloaded && hasActiveControl && surveillance >= 2 && (persistent || overlay || clustered) -> SpywareReviewLevel.HIGH
            hasActiveControl && activeControls >= 2 && surveillance >= 3 && persistent -> SpywareReviewLevel.HIGH
            // Broad privacy access is common in legitimate social, camera, navigation,
            // and messaging apps. It is only HIGH when paired with an active privileged
            // control and an additional persistence/overlay/cluster signal. Permissions
            // alone remain LOW or REVIEW, never a malware-like HIGH verdict.
            surveillance >= 5 && hasActiveControl && (persistent || overlay || clustered) -> SpywareReviewLevel.HIGH
            sideloaded && (controls >= 1 || overlay) && surveillance >= 1 -> SpywareReviewLevel.REVIEW
            clustered && (sideloaded || controls >= 1 || persistent) -> SpywareReviewLevel.REVIEW
            SpywareCapabilitySignal.INPUT_METHOD_SERVICE in signals && surveillance >= 2 -> SpywareReviewLevel.REVIEW
            SpywareCapabilitySignal.AUDIO_RECORDING_SERVICE in signals && (surveillance >= 2 || SpywareCapabilitySignal.QUERY_ALL_PACKAGES in signals) -> SpywareReviewLevel.REVIEW
            surveillance >= 4 && (SpywareCapabilitySignal.CAMERA_MIC_COMBO in signals || SpywareCapabilitySignal.SURVEILLANCE_COMBO in signals) -> SpywareReviewLevel.REVIEW
            controls >= 2 && (surveillance >= 2 || persistent) -> SpywareReviewLevel.REVIEW
            surveillance >= 4 && (persistent || overlay || SpywareCapabilitySignal.QUERY_ALL_PACKAGES in signals) -> SpywareReviewLevel.REVIEW
            else -> SpywareReviewLevel.LOW
        }

        // Keep the numeric score aligned with the corroborated policy level. The
        // floor is applied only after the multi-signal level has been established,
        // so ordinary messaging/privacy permissions can never become spyware merely
        // by accumulating permission points.
        score = when (level) {
            SpywareReviewLevel.HIGH -> maxOf(score, 65)
            SpywareReviewLevel.REVIEW -> maxOf(score, 35)
            SpywareReviewLevel.LOW -> minOf(score, 29)
        }.coerceIn(0, 100)

        return SpywareRiskAssessment(score, level, signals)
    }
}
