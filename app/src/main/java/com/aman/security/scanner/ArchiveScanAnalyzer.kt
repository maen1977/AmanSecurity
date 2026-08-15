package com.aman.security.scanner

import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipInputStream

/**
 * Bounded, read-only inspection of ZIP-family containers. It never extracts
 * entries to disk and stops before archive contents can consume excessive RAM,
 * CPU, or battery.
 *
 * If the bounded inspection cannot finish, the result is explicitly marked as
 * limited so callers do not accidentally present the archive as clean.
 */
class ArchiveScanAnalyzer(
    private val findSignature: (String) -> ThreatSignature?
) {
    fun scan(input: InputStream): ArchiveScanFinding? {
        val zip = runCatching { ZipInputStream(input) }.getOrNull() ?: return null
        var inspectedEntries = 0
        var totalBytes = 0L
        var scanLimited = false
        var limitedEntryName = "archive"
        return runCatching {
            zip.use { archive ->
                while (true) {
                    val entry = archive.nextEntry ?: break
                    if (entry.isDirectory) continue
                    if (inspectedEntries >= MAX_ENTRIES) {
                        limitedEntryName = entry.name.take(MAX_ENTRY_NAME_LENGTH)
                        scanLimited = true
                        return@use
                    }

                    val name = entry.name.take(MAX_ENTRY_NAME_LENGTH)
                    limitedEntryName = name
                    val digest = MessageDigest.getInstance("SHA-256")
                    val buffer = ByteArray(BUFFER_SIZE)
                    var entryBytes = 0L
                    var entryLimited = false
                    while (true) {
                        val read = archive.read(buffer)
                        if (read <= 0) break
                        entryBytes += read
                        totalBytes += read
                        if (entryBytes > MAX_ENTRY_BYTES || totalBytes > MAX_TOTAL_BYTES) {
                            entryLimited = true
                            scanLimited = true
                            break
                        }
                        digest.update(buffer, 0, read)
                    }
                    if (entryLimited) return@use

                    val sha256 = digest.digest().toHex()
                    val signature = findSignature(sha256)
                    val misleading = hasMisleadingDoubleExtension(name)
                    if (signature != null || misleading) {
                        return@runCatching ArchiveScanFinding(
                            entryName = name,
                            entrySha256 = sha256,
                            signatureId = signature?.id,
                            knownThreat = signature?.classification == ScanClassification.KNOWN_THREAT,
                            misleadingExtension = misleading
                        )
                    }
                    inspectedEntries++
                }

                if (scanLimited) {
                    ArchiveScanFinding(
                        entryName = limitedEntryName,
                        entrySha256 = "",
                        signatureId = null,
                        knownThreat = false,
                        misleadingExtension = false,
                        scanLimited = true
                    )
                } else {
                    null
                }
            }
        }.getOrNull()
    }

    private fun hasMisleadingDoubleExtension(name: String): Boolean {
        val lower = name.lowercase()
        val executableEndings = listOf(".apk", ".exe", ".scr", ".bat", ".cmd", ".com", ".jar", ".dex")
        val decoyEndings = listOf(".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".txt")
        return executableEndings.any { executable ->
            lower.endsWith(executable) && decoyEndings.any { decoy -> lower.contains("$decoy$executable") }
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    companion object {
        private const val BUFFER_SIZE = 16 * 1024
        private const val MAX_ENTRIES = 128
        private const val MAX_ENTRY_BYTES = 8L * 1024L * 1024L
        private const val MAX_TOTAL_BYTES = 16L * 1024L * 1024L
        private const val MAX_ENTRY_NAME_LENGTH = 240
    }
}

data class ArchiveScanFinding(
    val entryName: String,
    val entrySha256: String,
    val signatureId: String?,
    val knownThreat: Boolean,
    val misleadingExtension: Boolean,
    val scanLimited: Boolean = false
)
