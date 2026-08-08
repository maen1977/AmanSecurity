package com.aman.security.scanner

enum class ScanClassification {
    NO_KNOWN_THREAT,
    UNKNOWN_APK,
    SUSPICIOUS,
    KNOWN_THREAT,
    TEST_SIGNATURE
}

enum class ScanDetectionReason {
    NO_SIGNATURE,
    UNKNOWN_APK,
    DOUBLE_EXTENSION,
    APK_STATIC_HIGH_RISK,
    APK_INVALID,
    APK_IDENTITY_MATCH,
    APK_IDENTITY_TEST,
    KNOWN_FILE_SIGNATURE,
    TEST_SIGNATURE
}

data class ThreatSignature(
    val sha256: String,
    val id: String,
    val classification: ScanClassification
)

data class ScanResult(
    val fileName: String,
    val sizeBytes: Long,
    val sha256: String,
    val classification: ScanClassification,
    val signatureId: String? = null,
    val detectionReason: ScanDetectionReason = ScanDetectionReason.NO_SIGNATURE,
    val apkAnalysis: ApkStaticAnalysis? = null
)
