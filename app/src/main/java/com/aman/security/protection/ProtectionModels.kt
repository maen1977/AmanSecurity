package com.aman.security.protection

enum class ProtectionEventType {
    FILE,
    APP
}

enum class ProtectionSeverity {
    /** A heuristic signal that is not proof of malware and must not raise a high-risk alert. */
    REVIEW,
    HIGH_RISK,
    KNOWN_THREAT
}

data class ProtectionEvent(
    val id: String,
    val type: ProtectionEventType,
    val displayName: String,
    val detail: String?,
    val severity: ProtectionSeverity,
    val detectedAt: Long
)

data class ProtectedFolderAlertFinding(
    val displayName: String,
    val location: String,
    val sha256: String,
    val severity: ProtectionSeverity
)

data class ProtectedFolderScanSummary(
    val scannedFiles: Int,
    val skippedUnchanged: Int,
    val alerts: Int,
    val knownThreats: Int,
    val highRisk: Int,
    val inaccessibleFiles: Int,
    val truncated: Boolean,
    val permissionLost: Boolean,
    val findings: List<ProtectedFolderAlertFinding> = emptyList()
)
