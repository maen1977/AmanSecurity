package com.aman.security.scanner

/**
 * Presentation policy for the manual Full scan.
 *
 * Capability-only evidence is useful for the Permissions Control page, but it is not enough to
 * interrupt a Full scan with an app warning. A non-store app with a strong verdict remains
 * reviewable; confirmed threats always remain visible.
 */
object InstalledAppReviewPolicy {
    fun shouldSurfaceInFullScan(result: InstalledAppScanResult): Boolean = when {
        result.riskLevel == AppRiskLevel.KNOWN_THREAT -> true
        result.installSource == AppInstallSource.LOCAL_FILE ||
            result.installSource == AppInstallSource.DOWNLOADED_FILE -> result.riskLevel == AppRiskLevel.MEDIUM ||
            result.riskLevel == AppRiskLevel.HIGH
        else -> result.riskLevel == AppRiskLevel.HIGH
    }
}
