package com.aman.security.scanner

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns

class FileScanner(
    private val resolver: ContentResolver,
    private val database: SignatureDatabase
) {
    fun scan(uri: Uri): ScanResult {
        val meta = queryMetadata(uri)
        val sha256 = resolver.openInputStream(uri)?.use(Sha256::fromStream)
            ?: throw IllegalStateException()

        val signature = database.find(sha256)
        val classification = when {
            signature != null -> signature.classification
            hasMisleadingDoubleExtension(meta.name) -> ScanClassification.SUSPICIOUS
            meta.name.endsWith(".apk", ignoreCase = true) -> ScanClassification.UNKNOWN_APK
            else -> ScanClassification.NO_KNOWN_THREAT
        }

        return ScanResult(
            fileName = meta.name,
            sizeBytes = meta.size,
            sha256 = sha256,
            classification = classification,
            signatureId = signature?.id
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
