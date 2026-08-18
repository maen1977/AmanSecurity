package com.aman.security.security

enum class SecurityAuditSeverity {
    INFO,
    WARNING,
    HIGH
}

data class SecurityAuditFinding(
    val id: String,
    val severity: SecurityAuditSeverity
)

data class DeviceSecurityAudit(
    val screenLockSecure: Boolean,
    val developerOptionsEnabled: Boolean,
    val adbEnabled: Boolean,
    val automaticTimeEnabled: Boolean,
    val automaticTimeZoneEnabled: Boolean,
    val rootSignals: Int,
    val securityPatch: String,
    val findings: List<SecurityAuditFinding>
)

enum class NetworkTransportType {
    NONE,
    WIFI,
    CELLULAR,
    ETHERNET,
    VPN,
    OTHER
}

data class NetworkSecurityAudit(
    val connected: Boolean,
    val validated: Boolean,
    val captivePortal: Boolean,
    val vpnActive: Boolean,
    val privateDnsActive: Boolean,
    val metered: Boolean,
    val transport: NetworkTransportType,
    val findings: List<SecurityAuditFinding>
)

data class PrivacyAppExposure(
    val appName: String,
    val packageName: String,
    val grantedSensitivePermissions: Int,
    val grantedPermissions: List<String> = emptyList(),
    val isTrustedInstall: Boolean = false,
    /** Normalized install provenance used to invalidate legacy privacy-only findings safely. */
    val installSource: String = ""
)

data class PrivacyPermissionAudit(
    val scannedApps: Int,
    val appsWithSensitivePermissions: Int,
    val elevatedPermissionApps: Int,
    val totalGrantedSensitivePermissions: Int,
    val findings: List<SecurityAuditFinding>,
    val reviewApps: List<PrivacyAppExposure> = emptyList()
)

data class SecurityAuditSummary(
    val device: DeviceSecurityAudit,
    val network: NetworkSecurityAudit,
    val privacy: PrivacyPermissionAudit
) {
    val highFindings: Int = allFindings().count { it.severity == SecurityAuditSeverity.HIGH }
    val warningFindings: Int = allFindings().count { it.severity == SecurityAuditSeverity.WARNING }

    /** Small posture penalty only. This is not a malware probability or certification score. */
    val posturePenalty: Int = (
        highFindings * 12 + warningFindings * 4 + privacy.elevatedPermissionApps.coerceAtMost(3)
    ).coerceAtMost(35)

    private fun allFindings(): List<SecurityAuditFinding> =
        device.findings + network.findings + privacy.findings
}
