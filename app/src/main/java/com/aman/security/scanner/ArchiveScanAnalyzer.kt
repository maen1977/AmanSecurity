package com.aman.security.scanner

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipInputStream

/**
 * Bounded, read-only inspection of ZIP-family containers. It never extracts
 * entries to disk and stops before archive contents can consume excessive RAM,
 * CPU, or battery.
 *
 * A nested executable name is not malware evidence by itself. Every entry is
 * hashed before any optional nested inspection, so an exact threat signature
 * remains detectable while ordinary APK/JAR/DEX payloads remain unreported.
 * Only a genuinely misleading double extension is a review signal.
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
                val buffer = ByteArray(BUFFER_SIZE)
                while (true) {
                    val entry = archive.nextEntry ?: break
                    if (entry.isDirectory) continue
                    if (inspectedEntries >= MAX_ENTRIES) {
                        limitedEntryName = entry.name.take(MAX_ENTRY_NAME_LENGTH)
                        scanLimited = true
                        break
                    }

                    val name = entry.name.take(MAX_ENTRY_NAME_LENGTH)
                    limitedEntryName = name
                    val lowerName = name.lowercase()

                    val nestedCandidate = isNestedArchiveName(lowerName)
                    val digest = MessageDigest.getInstance("SHA-256")
                    val nestedData = if (nestedCandidate) ByteArrayOutputStream() else null
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
                        nestedData?.write(buffer, 0, read)
                    }
                    if (entryLimited) break

                    // Hash the complete entry before looking at its filename or contents.
                    // This preserves exact-hash detection for an APK/JAR/DEX inside ZIP.
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

                    // The bounded nested scan is advisory only. Unsigned/unknown nested
                    // executables remain unreported, while their exact inner signatures can
                    // still produce a confirmed threat result.
                    if (nestedData != null) {
                        val nested = scanNested(nestedData.toByteArray(), buffer)
                        if (nested?.scanLimited == true) scanLimited = true
                        if (nested?.knownThreat == true || nested?.misleadingExtension == true) {
                            return@runCatching nested
                        }
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

    /**
     * Opens a nested archive exactly once and hashes its inner entries against
     * the signature database. Bounded by MAX_NESTED_ENTRIES and MAX_TOTAL_BYTES
     * so it can never consume unbounded memory, CPU, or battery.
     */
    private fun scanNested(nestedData: ByteArray, buffer: ByteArray): ArchiveScanFinding? = runCatching {
        if (nestedData.isEmpty()) return@runCatching null
        val nestedZip = ZipInputStream(nestedData.inputStream())
        nestedZip.use { nestedArchive ->
            var nestedInspected = 0
            var nestedTotalBytes = 0L
            while (true) {
                val entry = nestedArchive.nextEntry ?: break
                if (entry.isDirectory) continue
                if (nestedInspected >= MAX_NESTED_ENTRIES) {
                    return@use ArchiveScanFinding(
                        entryName = "nested:$MAX_NESTED_ENTRIES",
                        entrySha256 = "",
                        signatureId = null,
                        knownThreat = false,
                        misleadingExtension = false,
                        scanLimited = true
                    )
                }

                val digest = MessageDigest.getInstance("SHA-256")
                var entryBytes = 0L
                var entryLimited = false
                while (true) {
                    val read = nestedArchive.read(buffer)
                    if (read <= 0) break
                    entryBytes += read
                    nestedTotalBytes += read
                    if (entryBytes > MAX_ENTRY_BYTES || nestedTotalBytes > MAX_TOTAL_BYTES) {
                        entryLimited = true
                        break
                    }
                    digest.update(buffer, 0, read)
                }
                val name = entry.name.take(MAX_ENTRY_NAME_LENGTH)
                if (entryLimited) {
                    return@use ArchiveScanFinding(
                        entryName = "nested:$name",
                        entrySha256 = "",
                        signatureId = null,
                        knownThreat = false,
                        misleadingExtension = false,
                        scanLimited = true
                    )
                }

                val sha256 = digest.digest().toHex()
                val signature = findSignature(sha256)
                val misleading = hasMisleadingDoubleExtension(name)
                if (signature != null || misleading) {
                    return@use ArchiveScanFinding(
                        entryName = "nested:$name",
                        entrySha256 = sha256,
                        signatureId = signature?.id,
                        knownThreat = signature?.classification == ScanClassification.KNOWN_THREAT,
                        misleadingExtension = misleading
                    )
                }
                nestedInspected++
            }
            null
        }
    }.getOrNull()

    private fun isNestedArchiveName(lowerName: String): Boolean = listOf(
        ".zip", ".apk", ".aab", ".aar", ".jar", ".apks", ".xapk", ".apkm"
    ).any { lowerName.endsWith(it) }

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
        private const val MAX_NESTED_ENTRIES = 32
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
