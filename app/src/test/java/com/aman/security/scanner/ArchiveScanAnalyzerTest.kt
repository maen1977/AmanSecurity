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
    fun marksArchiveLimitedWhenEntryCountExceedsBound() {
        val entries = Array(129) { index -> "entry-$index.txt" to "payload-$index" }
        val archive = zipOf(*entries)

        val finding = ArchiveScanAnalyzer { null }.scan(ByteArrayInputStream(archive))

        assertTrue(finding?.scanLimited == true)
        assertEquals("entry-128.txt", finding?.entryName)
    }

    @Test
    fun doesNotMarkArchiveLimitedAtExactEntryBound() {
        val entries = Array(128) { index -> "entry-$index.txt" to "payload-$index" }
        val archive = zipOf(*entries)

        val finding = ArchiveScanAnalyzer { null }.scan(ByteArrayInputStream(archive))

        assertTrue(finding == null)
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

    private fun zipOfBinary(vararg entries: Pair<String, ByteArray>): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content)
                zip.closeEntry()
            }
        }
        return output.toByteArray()
    }

    @Test
    fun ignoresUnsignedExecutablePayloadNestedInsideArchive() {
        val archive = zipOf("holiday.jpg" to "photo data", "setup.apk" to "fake installer")
        val finding = ArchiveScanAnalyzer { null }.scan(ByteArrayInputStream(archive))
        assertTrue("ordinary nested APK must not be a finding", finding == null)
    }

    @Test
    fun detectsKnownSignatureInExecutablePayloadNestedInsideArchive() {
        val payload = "known installer payload".toByteArray()
        val sha256 = MessageDigest.getInstance("SHA-256")
            .digest(payload)
            .joinToString("") { "%02x".format(it) }
        val archive = zipOfBinary("setup.apk" to payload)

        val finding = ArchiveScanAnalyzer { hash ->
            if (hash == sha256) ThreatSignature(hash, "TEST-NESTED-APK", ScanClassification.KNOWN_THREAT) else null
        }.scan(ByteArrayInputStream(archive))

        assertTrue("expected confirmed nested APK threat", finding?.knownThreat == true)
        assertEquals("setup.apk", finding?.entryName)
        assertEquals("TEST-NESTED-APK", finding?.signatureId)
        assertEquals(sha256, finding?.entrySha256)
        assertTrue("confirmed executable entry is not a misleading-name finding", finding?.misleadingExtension == false)
    }

    @Test
    fun hashesEntriesInsideNestedZipArchive() {
        val innerPayload = "nested known threat"
        val sha256 = MessageDigest.getInstance("SHA-256")
            .digest(innerPayload.toByteArray())
            .joinToString("") { "%02x".format(it) }
        val inner = zipOf("threat.bin" to innerPayload)
        val outer = zipOfBinary("container.zip" to inner)
        val finding = ArchiveScanAnalyzer { hash ->
            if (hash == sha256) ThreatSignature(hash, "TEST-NESTED", ScanClassification.KNOWN_THREAT) else null
        }.scan(ByteArrayInputStream(outer))
        assertTrue("expected known threat inside nested archive", finding?.knownThreat == true)
        assertEquals("TEST-NESTED", finding?.signatureId)
        assertTrue("expected nested entry name prefix", finding?.entryName?.startsWith("nested:") == true)
    }

    @Test
    fun reportsLimitedWhenNestedEntryCountExceedsBound() {
        val entries = Array(33) { index -> "nested-$index.bin" to "payload-$index" }
        val inner = zipOf(*entries)
        val outer = zipOfBinary("container.zip" to inner)
        val finding = ArchiveScanAnalyzer { null }.scan(ByteArrayInputStream(outer))
        assertTrue("expected limited nested scan", finding?.scanLimited == true)
    }
}
