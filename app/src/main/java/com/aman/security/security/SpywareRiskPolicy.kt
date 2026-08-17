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
 * Common camera, microphone, contacts, location, call-log, media, boot, and overlay
 * capabilities are normal for many messaging, calling, navigation, accessibility,
 * and device-management apps. Escalation therefore requires either an active
 * privileged control or confirmed sideloading together with corroborating signals.
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
        val corroboratedControl = hasActiveControl || sideloaded

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
            surveillance >= 5 && hasActiveControl && (persistent || overlay || clustered) -> SpywareReviewLevel.HIGH

            // A sideloaded package with a declared privileged control or overlay and
            // corroborating surveillance is worth a review, even before the control is active.
            sideloaded && (controls >= 1 || overlay) && surveillance >= 1 -> SpywareReviewLevel.REVIEW
            // Permission clusters alone are common in legitimate communication apps.
            clustered && corroboratedControl -> SpywareReviewLevel.REVIEW
            // Input methods are a special control surface; keep review when combined
            // with surveillance, but do not treat ordinary audio/camera apps alike.
            SpywareCapabilitySignal.INPUT_METHOD_SERVICE in signals && surveillance >= 2 -> SpywareReviewLevel.REVIEW
            // An audio recording service is not suspicious without active control or
            // confirmed sideloading; messaging and recorder apps commonly declare it.
            SpywareCapabilitySignal.AUDIO_RECORDING_SERVICE in signals &&
                corroboratedControl && (surveillance >= 2 || SpywareCapabilitySignal.QUERY_ALL_PACKAGES in signals) -> SpywareReviewLevel.REVIEW
            // Camera/microphone and broad surveillance combinations are privacy context
            // only unless paired with active control or confirmed sideloading.
            surveillance >= 4 && corroboratedControl &&
                (SpywareCapabilitySignal.CAMERA_MIC_COMBO in signals || SpywareCapabilitySignal.SURVEILLANCE_COMBO in signals) -> SpywareReviewLevel.REVIEW
            controls >= 2 && corroboratedControl && (surveillance >= 2 || persistent) -> SpywareReviewLevel.REVIEW
            surveillance >= 4 && corroboratedControl &&
                (persistent || overlay || SpywareCapabilitySignal.QUERY_ALL_PACKAGES in signals) -> SpywareReviewLevel.REVIEW
            else -> SpywareReviewLevel.LOW
        }

        // Keep the numeric score aligned with the corroborated policy level. Ordinary
        // permissions remain invisible to the spyware-review list because they are LOW.
        score = when (level) {
            SpywareReviewLevel.HIGH -> maxOf(score, 65)
            SpywareReviewLevel.REVIEW -> maxOf(score, 35)
            SpywareReviewLevel.LOW -> minOf(score, 29)
        }.coerceIn(0, 100)

        return SpywareRiskAssessment(score, level, signals)
    }
}
