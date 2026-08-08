package com.aman.security.security

import com.aman.security.scanner.ScanClassification

data class QuarantineEntry(
    val id: String,
    val fileName: String,
    val sizeBytes: Long,
    val sha256: String,
    val signatureId: String?,
    val classification: ScanClassification,
    val quarantinedAt: Long,
    val blobName: String
)

data class ExclusionEntry(
    val sha256: String,
    val fileName: String,
    val addedAt: Long
)

data class ScanHistoryEntry(
    val id: String,
    val fileName: String,
    val sha256: String,
    val classification: ScanClassification,
    val scannedAt: Long
)
