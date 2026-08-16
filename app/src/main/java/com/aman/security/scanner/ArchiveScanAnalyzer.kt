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
 *
 * 5.0.0 — Two extra layers: a nested executable payload (APK/JAR/DEX inside a
 * regular archive) is flagged immediately as misleading, and nested archives
 * are opened once (depth two maximum) and their inner entries hashed in
 * memory against the threat database.
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

                    // 5.0.0 — Hidden executable payload: an APK, JAR or DEX
                    // nested inside a regular archive is a classic drop-stage
                    // tactic and always deserves review.
                    if (lowerName.endsWith(".apk") || lowerName.endsWith(".jar") || lowerName.endsWith(".dex")) {
                        return@runCatching ArchiveScanFinding(
                            entryName = name,
                            entrySha256 = "",
                            signatureId = null,
                            knownThreat = false,
                            misleadingExtension = true
                        )
                    }

                    // 5.0.0 — Bounded nested-archive inspection (depth two max).
                    val nested = if (lowerName.endsWith(".zip") || lowerName.endsWith(".apk") ||
                        lowerName.endsWith(".jar")) scanNested(archive, buffer, totalBytes) else null
                    if (nested != null) {
                        if (nested.scanLimited) scanLimited = true
                        if (nested.knownThreat || nested.misleadingExtension) {
                            return@runCatching nested
                        }
                        inspectedEntries++
                        continue
                    }

                    val digest = MessageDigest.getInstance("SHA-256")
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
                    if (entryLimited) break
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

    /**
     * Opens a nested archive exactly once and hashes its inner entries against
     * the signature database. Bounded by MAX_NESTED_ENTRIES and MAX_TOTAL_BYTES
     * so it can never consume unbounded memory, CPU, or battery.
     */
    private fun scanNested(
        outer: ZipInputStream,
        buffer: ByteArray,
        totalBytes: Long
    ): ArchiveScanFinding? {
        val nestedData = mutableListOf<Byte>()
        var nestedBytes = 0L
        var nestedLimited = false
        while (true) {
            val read = outer.read(buffer)
            if (read <= 0) break
            nestedBytes += read
            if (nestedBytes > MAX_ENTRY_BYTES || nestedBytes > MAX_TOTAL_BYTES) {
                nestedLimited = true
                break
            }
            nestedData.addAll(buffer.take(read))
        }
        if (nestedLimited || nestedData.isEmpty()) return null
        val nestedStream = nestedData.toByteArray().inputStream()
        val nestedZip = runCatching { ZipInputStream(nestedStream) }.getOrNull() ?: return null
        return nestedZip.use { nestedArchive ->
            var nestedInspected = 0
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
                    if (entryBytes > MAX_ENTRY_BYTES) {
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
                val misleading = name.lowercase().let { lower ->
                    (lower.endsWith(".apk") || lower.endsWith(".jar") || lower.endsWith(".dex"))
                }
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
