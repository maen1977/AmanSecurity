package com.aman.security.protection

import com.aman.security.scanner.AppRiskLevel
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.ScanDetectionReason
import com.aman.security.scanner.ScanResult

object ProtectionPolicy {
    const val MAX_GENERAL_FILE_BYTES = 64L * 1024L * 1024L
    const val MAX_HIGH_INTEREST_FILE_BYTES = 512L * 1024L * 1024L
    const val MAX_DOCUMENTS_PER_RUN = 1500
    const val MAX_SCAN_FILES_PER_RUN = 120
    const val MAX_TREE_DEPTH = 16

    private val highInterestExtensions = setOf(
        "apk", "xapk", "apks", "apkm", "jar", "dex", "zip", "7z", "rar"
    )

    fun shouldScanFile(fileName: String, sizeBytes: Long): Boolean {
        if (sizeBytes == 0L) return false
        val extension = fileName.substringAfterLast('.', "").lowercase()
        val limit = if (extension in highInterestExtensions) {
            MAX_HIGH_INTEREST_FILE_BYTES
        } else {
            MAX_GENERAL_FILE_BYTES
        }
        return sizeBytes < 0L || sizeBytes <= limit
    }

    fun shouldNotifyFile(result: ScanResult, excluded: Boolean): Boolean {
        if (excluded) return false
        if (result.classification == ScanClassification.KNOWN_THREAT) return true
        return result.classification == ScanClassification.SUSPICIOUS &&
            result.detectionReason == ScanDetectionReason.APK_STATIC_HIGH_RISK
    }

    fun shouldNotifyApp(level: AppRiskLevel): Boolean =
        level == AppRiskLevel.HIGH || level == AppRiskLevel.KNOWN_THREAT

    fun severityForFile(result: ScanResult): ProtectionSeverity? = when {
        result.classification == ScanClassification.KNOWN_THREAT -> ProtectionSeverity.KNOWN_THREAT
        result.classification == ScanClassification.SUSPICIOUS &&
            result.detectionReason == ScanDetectionReason.APK_STATIC_HIGH_RISK -> ProtectionSeverity.HIGH_RISK
        else -> null
    }

    fun severityForApp(level: AppRiskLevel): ProtectionSeverity? = when (level) {
        AppRiskLevel.KNOWN_THREAT -> ProtectionSeverity.KNOWN_THREAT
        AppRiskLevel.HIGH -> ProtectionSeverity.HIGH_RISK
        else -> null
    }
}
