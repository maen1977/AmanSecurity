package com.aman.security.scanner

import com.aman.security.detection.DetectionVerdictLevel

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns

class FileScanner(
    private val resolver: ContentResolver,
    private val database: SignatureDatabase,
    private val apkStaticAnalyzer: ApkStaticAnalyzer? = null
) {
    fun scan(uri: Uri): ScanResult {
        val meta = queryMetadata(uri)
        val sha256 = resolver.openInputStream(uri)?.use(Sha256::fromStream)
            ?: throw IllegalStateException()

        val signature = database.find(sha256)
        val looksLikeApk = meta.name.endsWith(".apk", ignoreCase = true)
        val apkAnalysis = if (looksLikeApk) apkStaticAnalyzer?.analyze(uri, sha256) else null
        val identityIndicator = apkAnalysis?.identityIndicator
        val doubleExtension = hasMisleadingDoubleExtension(meta.name)

        val classification: ScanClassification
        val reason: ScanDetectionReason
        val signatureId: String?

        when {
            signature != null -> {
                classification = signature.classification
                reason = if (signature.classification == ScanClassification.TEST_SIGNATURE) {
                    ScanDetectionReason.TEST_SIGNATURE
                } else {
                    ScanDetectionReason.KNOWN_FILE_SIGNATURE
                }
                signatureId = signature.id
            }
            identityIndicator?.classification == ApkIdentityClassification.KNOWN_THREAT -> {
                classification = ScanClassification.KNOWN_THREAT
                reason = ScanDetectionReason.APK_IDENTITY_MATCH
                signatureId = identityIndicator.id
            }
            identityIndicator?.classification == ApkIdentityClassification.TEST_SIGNATURE -> {
                classification = ScanClassification.TEST_SIGNATURE
                reason = ScanDetectionReason.APK_IDENTITY_TEST
                signatureId = identityIndicator.id
            }
            apkAnalysis?.advancedVerdict?.level == DetectionVerdictLevel.KNOWN_THREAT -> {
                classification = ScanClassification.KNOWN_THREAT
                reason = ScanDetectionReason.APK_MULTI_ENGINE_KNOWN
                signatureId = apkAnalysis.advancedVerdict.confirmedReference
            }
            doubleExtension -> {
                classification = ScanClassification.SUSPICIOUS
                reason = ScanDetectionReason.DOUBLE_EXTENSION
                signatureId = null
            }
            apkAnalysis?.state == ApkAnalysisState.INVALID_APK -> {
                classification = ScanClassification.SUSPICIOUS
                reason = ScanDetectionReason.APK_INVALID
                signatureId = null
            }
            apkAnalysis?.state == ApkAnalysisState.VALID && apkAnalysis.riskLevel == ApkRiskLevel.HIGH -> {
                classification = ScanClassification.SUSPICIOUS
                reason = ScanDetectionReason.APK_STATIC_HIGH_RISK
                signatureId = null
            }
            looksLikeApk -> {
                classification = ScanClassification.UNKNOWN_APK
                reason = ScanDetectionReason.UNKNOWN_APK
                signatureId = null
            }
            else -> {
                classification = ScanClassification.NO_KNOWN_THREAT
                reason = ScanDetectionReason.NO_SIGNATURE
                signatureId = null
            }
        }

        return ScanResult(
            fileName = meta.name,
            sizeBytes = meta.size,
            sha256 = sha256,
            classification = classification,
            signatureId = signatureId,
            detectionReason = reason,
            apkAnalysis = apkAnalysis
        )
    }

    private fun queryMetadata(uri: Uri): FileMeta {
        var name = "—"
        var size = -1L
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (nameIndex >= 0) name = cursor.getString(nameIndex) ?: name
                    if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) size = cursor.getLong(sizeIndex)
                }
            }
        return FileMeta(name, size)
    }

    private fun hasMisleadingDoubleExtension(name: String): Boolean {
        val lower = name.lowercase()
        val executableEndings = listOf(".apk", ".exe", ".scr", ".bat", ".cmd", ".com", ".jar")
        val decoyEndings = listOf(".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".txt")
        return executableEndings.any { executable ->
            lower.endsWith(executable) && decoyEndings.any { decoy -> lower.contains("$decoy$executable") }
        }
    }

    private data class FileMeta(val name: String, val size: Long)
}
