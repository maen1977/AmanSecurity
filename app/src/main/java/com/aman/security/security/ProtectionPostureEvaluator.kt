package com.aman.security.security

enum class ProtectionPostureLevel {
    STRONG,
    ATTENTION,
    LIMITED
}

data class ProtectionPostureInput(
    val databaseHealthy: Boolean,
    val freshSources: Int,
    val totalSources: Int,
    val backgroundProtectionEnabled: Boolean,
    val webGuardActive: Boolean,
    val devicePatchKnown: Boolean,
    val devicePatchCurrent: Boolean,
    val integrityStatus: AppIntegrityStatus,
    /** A completed local web-shield/link-guard verification, not merely an enabled switch. */
    val webProtectionVerified: Boolean = false
)

data class ProtectionPosture(
    val score: Int,
    val level: ProtectionPostureLevel
)

/** A readiness score for enabled protection layers; it is not a malware-detection probability. */
object ProtectionPostureEvaluator {
    fun evaluate(input: ProtectionPostureInput): ProtectionPosture {
        var score = 0
        if (input.databaseHealthy) score += 25
        if (input.totalSources > 0) {
            score += ((input.freshSources.coerceIn(0, input.totalSources) * 20.0) / input.totalSources).toInt()
        }
        if (input.backgroundProtectionEnabled) score += 20
        if (input.webGuardActive) score += 15
        if (input.devicePatchKnown) score += if (input.devicePatchCurrent) 10 else 3
        score += when (input.integrityStatus) {
            AppIntegrityStatus.VERIFIED_RELEASE -> 10
            AppIntegrityStatus.UNPINNED_RELEASE -> 5
            AppIntegrityStatus.DEBUG_BUILD -> 3
            AppIntegrityStatus.UNKNOWN -> 2
            AppIntegrityStatus.SIGNATURE_MISMATCH -> 0
        }
        score = score.coerceIn(0, 100)
        // Do not present an unverified web layer as strong production readiness.
        if (!input.webProtectionVerified) score = minOf(score, 79)
        val level = when {
            input.integrityStatus == AppIntegrityStatus.SIGNATURE_MISMATCH -> ProtectionPostureLevel.LIMITED
            score < 55 -> ProtectionPostureLevel.LIMITED
            input.integrityStatus == AppIntegrityStatus.DEBUG_BUILD -> ProtectionPostureLevel.ATTENTION
            score >= 80 -> ProtectionPostureLevel.STRONG
            else -> ProtectionPostureLevel.ATTENTION
        }
        return ProtectionPosture(score, level)
    }
}
