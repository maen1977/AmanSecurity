package com.aman.security.scanner

import com.aman.security.detection.MultiEngineVerdict

enum class AppRiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    KNOWN_THREAT
}

enum class AppInstallSource {
    STORE,
    LOCAL_FILE,
    DOWNLOADED_FILE,
    OTHER,
    UNKNOWN
}

enum class AppRiskSignal {
    ACCESSIBILITY_SERVICE,
    OVERLAY,
    INSTALL_PACKAGES,
    SMS_ACCESS,
    CONTACTS_ACCESS,
    CALL_LOG_ACCESS,
    MICROPHONE,
    CAMERA,
    PRECISE_LOCATION,
    BOOT_START,
    NON_STORE_INSTALL
}

data class AppRiskInput(
    val requestedPermissions: Set<String>,
    val hasAccessibilityService: Boolean,
    val installSource: AppInstallSource,
    val knownThreatReference: String? = null
)

data class AppRiskEvaluation(
    val score: Int,
    val level: AppRiskLevel,
    val signals: Set<AppRiskSignal>
)

data class InstalledAppScanResult(
    val appName: String,
    val packageName: String,
    val versionName: String?,
    val installSource: AppInstallSource,
    val riskScore: Int,
    val riskLevel: AppRiskLevel,
    val signals: Set<AppRiskSignal>,
    val apkSha256: String?,
    val signingCertificateSha256: String?,
    val threatReference: String? = null,
    val advancedVerdict: MultiEngineVerdict? = null,
    val deepAnalysisPerformed: Boolean = false
)

data class InstalledAppsScanSummary(
    val scannedApps: Int,
    val reviewApps: Int,
    val highRiskApps: Int,
    val knownThreats: Int,
    val results: List<InstalledAppScanResult>
)
