package com.aman.security.scanner

import com.aman.security.detection.DetectionVerdictLevel

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import java.io.FileInputStream

enum class FileScanStage { HASHING, REPUTATION, APK_ANALYSIS, FINALIZING }

data class FileScanProgress(val percent: Int, val stage: FileScanStage, val fileName: String)

class FileScanner(
    private val resolver: ContentResolver,
    private val database: SignatureDatabase,
    private val apkStaticAnalyzer: ApkStaticAnalyzer? = null
) {
    private val archiveScanAnalyzer = ArchiveScanAnalyzer(database::find)

    fun scan(file: File, onProgress: ((FileScanProgress) -> Unit)? = null): ScanResult {
        require(file.isFile) { "Scan target is not a file" }
        val meta = FileMeta(file.name.ifBlank { "—" }, file.length())
        onProgress?.invoke(FileScanProgress(2, FileScanStage.HASHING, meta.name))
        val sha256 = FileInputStream(file).use { input ->
            Sha256.fromStream(input) { bytesRead ->
                val hashingPercent = if (meta.size > 0L) {
                    (2 + ((bytesRead.coerceAtMost(meta.size) * 66L) / meta.size).toInt()).coerceIn(2, 68)
                } else 35
                onProgress?.invoke(FileScanProgress(hashingPercent, FileScanStage.HASHING, meta.name))
            }
        }

        onProgress?.invoke(FileScanProgress(72, FileScanStage.REPUTATION, meta.name))
        val signature = database.find(sha256)
        val looksLikeApk = meta.name.endsWith(".apk", ignoreCase = true)
        if (looksLikeApk) onProgress?.invoke(FileScanProgress(78, FileScanStage.APK_ANALYSIS, meta.name))
        val apkAnalysis = if (looksLikeApk) apkStaticAnalyzer?.analyzeInstalledFile(file, sha256) else null
        val archiveFinding = if (isArchive(meta.name)) {
            runCatching { FileInputStream(file).use { archiveScanAnalyzer.scan(it) } }.getOrNull()
        } else {
            null
        }
        onProgress?.invoke(FileScanProgress(92, FileScanStage.FINALIZING, meta.name))
        val identityIndicator = apkAnalysis?.identityIndicator
        val doubleExtension = hasMisleadingDoubleExtension(meta.name)

        val classification: ScanClassification
        val reason: ScanDetectionReason
        val signatureId: String?
        when {
            signature != null -> {
                classification = signature.classification
                reason = if (signature.classification == ScanClassification.TEST_SIGNATURE) ScanDetectionReason.TEST_SIGNATURE else ScanDetectionReason.KNOWN_FILE_SIGNATURE
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
            archiveFinding?.knownThreat == true -> {
                classification = ScanClassification.KNOWN_THREAT
                reason = if (archiveFinding.isExecutableEntry()) {
                    ScanDetectionReason.ARCHIVE_EXECUTABLE_ENTRY
                } else {
                    ScanDetectionReason.ARCHIVE_KNOWN_SIGNATURE
                }
                signatureId = archiveFinding.signatureId
            }
            archiveFinding?.scanLimited == true -> {
                classification = ScanClassification.SUSPICIOUS
                reason = ScanDetectionReason.ARCHIVE_SCAN_LIMIT_REACHED
                signatureId = null
            }
            archiveFinding?.misleadingExtension == true -> {
                classification = ScanClassification.SUSPICIOUS
                reason = ScanDetectionReason.ARCHIVE_MISLEADING_ENTRY
                signatureId = null
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
        onProgress?.invoke(FileScanProgress(100, FileScanStage.FINALIZING, meta.name))
        return ScanResult(
            fileName = meta.name,
            sizeBytes = meta.size,
            sha256 = sha256,
            classification = classification,
            signatureId = signatureId,
            detectionReason = reason,
            apkAnalysis = apkAnalysis,
            archiveFinding = archiveFinding
        )
    }

    fun scan(uri: Uri, onProgress: ((FileScanProgress) -> Unit)? = null): ScanResult {
        val meta = queryMetadata(uri)
        onProgress?.invoke(FileScanProgress(2, FileScanStage.HASHING, meta.name))
        val sha256 = resolver.openInputStream(uri)?.use { input ->
            Sha256.fromStream(input) { bytesRead ->
                val hashingPercent = if (meta.size > 0L) {
                    (2 + ((bytesRead.coerceAtMost(meta.size) * 66L) / meta.size).toInt()).coerceIn(2, 68)
                } else 35
                onProgress?.invoke(FileScanProgress(hashingPercent, FileScanStage.HASHING, meta.name))
            }
        } ?: throw IllegalStateException()

        onProgress?.invoke(FileScanProgress(72, FileScanStage.REPUTATION, meta.name))
        val signature = database.find(sha256)
        val looksLikeApk = meta.name.endsWith(".apk", ignoreCase = true)
        if (looksLikeApk) onProgress?.invoke(FileScanProgress(78, FileScanStage.APK_ANALYSIS, meta.name))
        val apkAnalysis = if (looksLikeApk) apkStaticAnalyzer?.analyze(uri, sha256) else null
        val archiveFinding = if (isArchive(meta.name)) {
            runCatching { resolver.openInputStream(uri)?.use { archiveScanAnalyzer.scan(it) } }.getOrNull()
        } else {
            null
        }
        onProgress?.invoke(FileScanProgress(92, FileScanStage.FINALIZING, meta.name))
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
            archiveFinding?.knownThreat == true -> {
                classification = ScanClassification.KNOWN_THREAT
                reason = if (archiveFinding.isExecutableEntry()) {
                    ScanDetectionReason.ARCHIVE_EXECUTABLE_ENTRY
                } else {
                    ScanDetectionReason.ARCHIVE_KNOWN_SIGNATURE
                }
                signatureId = archiveFinding.signatureId
            }
            archiveFinding?.scanLimited == true -> {
                classification = ScanClassification.SUSPICIOUS
                reason = ScanDetectionReason.ARCHIVE_SCAN_LIMIT_REACHED
                signatureId = null
            }
            archiveFinding?.misleadingExtension == true -> {
                classification = ScanClassification.SUSPICIOUS
                reason = ScanDetectionReason.ARCHIVE_MISLEADING_ENTRY
                signatureId = null
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

        onProgress?.invoke(FileScanProgress(100, FileScanStage.FINALIZING, meta.name))
        return ScanResult(
            fileName = meta.name,
            sizeBytes = meta.size,
            sha256 = sha256,
            classification = classification,
            signatureId = signatureId,
            detectionReason = reason,
            apkAnalysis = apkAnalysis,
            archiveFinding = archiveFinding
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

    /**
     * Android package containers are ZIP-based and must be inspected by content,
     * not judged from their filename alone. Unsupported archive formats are left
     * to the normal hash/reputation path rather than pretending to be inspected.
     */
    private fun isArchive(name: String): Boolean = listOf(
        ".zip", ".jar", ".apk", ".aab", ".aar", ".apks", ".xapk", ".apkm"
    ).any {
        name.endsWith(it, ignoreCase = true)
    }

    private fun ArchiveScanFinding.isExecutableEntry(): Boolean {
        val lowerName = entryName.lowercase()
        return lowerName.endsWith(".apk") || lowerName.endsWith(".jar") || lowerName.endsWith(".dex")
    }

    private fun hasMisleadingDoubleExtension(name: String): Boolean {
        val lower = name.lowercase()
        val executableEndings = listOf(".apk", ".exe", ".scr", ".bat", ".cmd", ".com", ".jar", ".dex")
        val decoyEndings = listOf(".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".txt")
        return executableEndings.any { executable ->
            lower.endsWith(executable) && decoyEndings.any { decoy -> lower.contains("$decoy$executable") }
        }
    }

    private data class FileMeta(val name: String, val size: Long)
}
