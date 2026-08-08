package com.aman.security.scanner

enum class ScanClassification {
    NO_KNOWN_THREAT,
    UNKNOWN_APK,
    SUSPICIOUS,
    KNOWN_THREAT,
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
    val signatureId: String? = null
)
