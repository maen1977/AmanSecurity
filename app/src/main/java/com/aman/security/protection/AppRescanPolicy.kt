package com.aman.security.protection

import com.aman.security.scanner.AppRiskLevel
import com.aman.security.scanner.InstalledAppScanResult

/**
 * Prevents recurring background rescans from repeatedly notifying the user for
 * an unchanged finding. A new APK hash, version, risk level or confirmed
 * reference creates a new fingerprint and can notify again.
 */
object AppRescanPolicy {
    fun fingerprint(result: InstalledAppScanResult): String = listOf(
        result.riskLevel.name,
        result.versionName.orEmpty(),
        result.apkSha256.orEmpty(),
        result.signingCertificateSha256.orEmpty(),
        result.threatReference.orEmpty()
    ).joinToString("|")

    fun shouldNotify(previousFingerprint: String?, result: InstalledAppScanResult): Boolean {
        if (result.riskLevel != AppRiskLevel.HIGH && result.riskLevel != AppRiskLevel.KNOWN_THREAT) return false
        return previousFingerprint != fingerprint(result)
    }
}
