package com.aman.security.protection

import com.aman.security.scanner.AppRiskLevel
import com.aman.security.scanner.ScanClassification
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionPolicyTest {
    @Test
    fun `background alerts are limited to high risk and known threats`() {
        assertTrue(ProtectionPolicy.shouldNotifyApp(AppRiskLevel.HIGH))
        assertTrue(ProtectionPolicy.shouldNotifyApp(AppRiskLevel.KNOWN_THREAT))
        assertFalse(ProtectionPolicy.shouldNotifyApp(AppRiskLevel.MEDIUM))
        assertFalse(ProtectionPolicy.shouldNotifyApp(AppRiskLevel.LOW))
    }

    @Test
    fun `file exclusions suppress background alerts without changing classification`() {
        assertTrue(ProtectionPolicy.shouldNotifyFile(ScanClassification.KNOWN_THREAT, excluded = false))
        assertTrue(ProtectionPolicy.shouldNotifyFile(ScanClassification.SUSPICIOUS, excluded = false))
        assertFalse(ProtectionPolicy.shouldNotifyFile(ScanClassification.KNOWN_THREAT, excluded = true))
        assertFalse(ProtectionPolicy.shouldNotifyFile(ScanClassification.TEST_SIGNATURE, excluded = false))
        assertFalse(ProtectionPolicy.shouldNotifyFile(ScanClassification.UNKNOWN_APK, excluded = false))
    }

    @Test
    fun `folder scanning is bounded by file size and prioritizes archive app formats`() {
        assertTrue(ProtectionPolicy.shouldScanFile("sample.apk", 400L * 1024L * 1024L))
        assertFalse(ProtectionPolicy.shouldScanFile("sample.apk", 600L * 1024L * 1024L))
        assertTrue(ProtectionPolicy.shouldScanFile("note.txt", 20L * 1024L * 1024L))
        assertFalse(ProtectionPolicy.shouldScanFile("video.bin", 100L * 1024L * 1024L))
        assertFalse(ProtectionPolicy.shouldScanFile("empty.apk", 0L))
    }
}
