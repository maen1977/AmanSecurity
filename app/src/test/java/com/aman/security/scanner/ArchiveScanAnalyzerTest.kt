package com.aman.security.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ArchiveScanAnalyzerTest {
    @Test
    fun detectsMisleadingEntryNameWithoutSignature() {
        val archive = zipOf("holiday.jpg.apk" to "not an apk")

        val finding = ArchiveScanAnalyzer { null }.scan(ByteArrayInputStream(archive))

        assertTrue(finding?.misleadingExtension == true)
        assertEquals("holiday.jpg.apk", finding?.entryName)
    }

    @Test
    fun detectsKnownEntrySignatureInsideArchive() {
        val payload = "known payload".toByteArray()
        val sha256 = MessageDigest.getInstance("SHA-256")
            .digest(payload)
            .joinToString("") { "%02x".format(it) }
        val archive = zipOf("payload.bin" to payload.decodeToString())

        val finding = ArchiveScanAnalyzer { hash ->
            if (hash == sha256) ThreatSignature(hash, "TEST-ARCHIVE", ScanClassification.KNOWN_THREAT) else null
        }.scan(ByteArrayInputStream(archive))

        assertTrue(finding?.knownThreat == true)
        assertEquals("TEST-ARCHIVE", finding?.signatureId)
    }

    private fun zipOf(vararg entries: Pair<String, String>): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content.toByteArray())
                zip.closeEntry()
            }
        }
        return output.toByteArray()
    }
}
