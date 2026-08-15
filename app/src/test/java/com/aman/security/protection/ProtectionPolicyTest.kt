package com.aman.security.protection

import com.aman.security.scanner.AppRiskLevel
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.ScanDetectionReason
import com.aman.security.scanner.ScanResult
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionPolicyTest {
    @Test
    fun `background app alerts are limited to high risk and known threats`() {
        assertTrue(ProtectionPolicy.shouldNotifyApp(AppRiskLevel.HIGH))
        assertTrue(ProtectionPolicy.shouldNotifyApp(AppRiskLevel.KNOWN_THREAT))
        assertFalse(ProtectionPolicy.shouldNotifyApp(AppRiskLevel.MEDIUM))
        assertFalse(ProtectionPolicy.shouldNotifyApp(AppRiskLevel.LOW))
    }

    @Test
    fun `background file alerts suppress low confidence suspicious reasons`() {
        val known = result(ScanClassification.KNOWN_THREAT, ScanDetectionReason.KNOWN_FILE_SIGNATURE)
        val highApk = result(ScanClassification.SUSPICIOUS, ScanDetectionReason.APK_STATIC_HIGH_RISK)
        val doubleExtension = result(ScanClassification.SUSPICIOUS, ScanDetectionReason.DOUBLE_EXTENSION)
        val invalidApk = result(ScanClassification.SUSPICIOUS, ScanDetectionReason.APK_INVALID)
        val limitedArchive = result(ScanClassification.SUSPICIOUS, ScanDetectionReason.ARCHIVE_SCAN_LIMIT_REACHED)
        assertTrue(ProtectionPolicy.shouldNotifyFile(known, excluded = false))
        assertTrue(ProtectionPolicy.shouldNotifyFile(highApk, excluded = false))
        assertTrue(ProtectionPolicy.shouldNotifyFile(limitedArchive, excluded = false))
        assertFalse(ProtectionPolicy.shouldNotifyFile(doubleExtension, excluded = false))
        assertFalse(ProtectionPolicy.shouldNotifyFile(invalidApk, excluded = false))
        assertFalse(ProtectionPolicy.shouldNotifyFile(known, excluded = true))
    }

    @Test
    fun `folder scanning is bounded by file size and prioritizes archive app formats`() {
        assertTrue(ProtectionPolicy.shouldScanFile("sample.apk", 400L * 1024L * 1024L))
        assertFalse(ProtectionPolicy.shouldScanFile("sample.apk", 600L * 1024L * 1024L))
        assertTrue(ProtectionPolicy.shouldScanFile("note.txt", 20L * 1024L * 1024L))
        assertFalse(ProtectionPolicy.shouldScanFile("video.bin", 100L * 1024L * 1024L))
        assertFalse(ProtectionPolicy.shouldScanFile("empty.apk", 0L))
    }

    private fun result(classification: ScanClassification, reason: ScanDetectionReason) = ScanResult(
        fileName = "sample.apk",
        sizeBytes = 1,
        sha256 = "0".repeat(64),
        classification = classification,
        detectionReason = reason
    )
}
