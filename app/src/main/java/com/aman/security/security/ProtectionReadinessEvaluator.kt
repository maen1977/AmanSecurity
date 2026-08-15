package com.aman.security.security

enum class ProtectionReadinessLevel {
    READY,
    ATTENTION,
    LIMITED
}

data class ProtectionReadinessInput(
    val databaseHealthy: Boolean,
    val serviceHealthy: Boolean,
    val appInstallMonitorEnabled: Boolean,
    val downloadsProtectionReady: Boolean,
    val webProtectionActive: Boolean,
    val webProtectionVerified: Boolean,
    val intrusionCheckReady: Boolean,
    val dataExfiltrationCheckReady: Boolean
)

data class ProtectionReadiness(
    val readyChecks: Int,
    val totalChecks: Int,
    val level: ProtectionReadinessLevel
)

/**
 * Small, deterministic, on-device readiness summary.
 * This is a coverage/readiness indicator, not a malware-detection probability.
 */
object ProtectionReadinessEvaluator {
    fun evaluate(input: ProtectionReadinessInput): ProtectionReadiness {
        val checks = listOf(
            input.databaseHealthy,
            input.serviceHealthy,
            input.appInstallMonitorEnabled,
            input.downloadsProtectionReady,
            input.webProtectionActive,
            input.webProtectionVerified,
            input.intrusionCheckReady,
            input.dataExfiltrationCheckReady
        )
        val readyChecks = checks.count { it }
        val totalChecks = checks.size
        val level = when {
            !input.databaseHealthy || !input.serviceHealthy -> ProtectionReadinessLevel.LIMITED
            readyChecks == totalChecks -> ProtectionReadinessLevel.READY
            readyChecks >= totalChecks - 2 -> ProtectionReadinessLevel.ATTENTION
            else -> ProtectionReadinessLevel.LIMITED
        }
        return ProtectionReadiness(readyChecks, totalChecks, level)
    }
}
