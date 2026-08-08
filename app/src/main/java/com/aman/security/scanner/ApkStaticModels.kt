package com.aman.security.scanner

enum class ApkAnalysisState {
    VALID,
    INVALID_APK,
    LIMIT_EXCEEDED,
    SOURCE_CHANGED,
    FAILED
}

enum class ApkRiskLevel {
    LOW,
    REVIEW,
    HIGH
}

enum class ApkRiskSignal {
    ACCESSIBILITY_SERVICE,
    DEVICE_ADMIN_RECEIVER,
    NOTIFICATION_LISTENER_SERVICE,
    VPN_SERVICE,
    OVERLAY_PERMISSION,
    REQUEST_INSTALL_PACKAGES,
    SMS_ACCESS,
    CONTACTS_ACCESS,
    CALL_LOG_ACCESS,
    MICROPHONE,
    CAMERA,
    PRECISE_LOCATION,
    BOOT_START,
    QUERY_ALL_PACKAGES,
    DEBUGGABLE,
    NATIVE_CODE,
    MANY_DEX_FILES,
    DYNAMIC_CODE_LOADING,
    RUNTIME_EXECUTION,
    SMS_API,
    DEVICE_IDENTIFIER_API
}

enum class ApkIndicatorKind {
    SIGNER,
    PACKAGE
}

enum class ApkIdentityClassification {
    KNOWN_THREAT,
    TEST_SIGNATURE
}

data class ApkIdentityIndicator(
    val kind: ApkIndicatorKind,
    val sha256: String,
    val id: String,
    val classification: ApkIdentityClassification
)

data class ApkRiskEvaluation(
    val score: Int,
    val level: ApkRiskLevel,
    val signals: Set<ApkRiskSignal>
)

data class ApkStaticAnalysis(
    val state: ApkAnalysisState,
    val riskScore: Int = 0,
    val riskLevel: ApkRiskLevel = ApkRiskLevel.LOW,
    val signals: Set<ApkRiskSignal> = emptySet(),
    val requestedPermissionCount: Int = 0,
    val componentCount: Int = 0,
    val dexFileCount: Int = 0,
    val nativeLibraryCount: Int = 0,
    val signingCertificateSha256: String? = null,
    val identityIndicator: ApkIdentityIndicator? = null,
    val codeScanTruncated: Boolean = false
)
