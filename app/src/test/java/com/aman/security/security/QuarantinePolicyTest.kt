package com.aman.security.security

import com.aman.security.scanner.ScanClassification
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QuarantinePolicyTest {
    @Test
    fun `no known threat result does not offer quarantine`() {
        assertFalse(QuarantinePolicy.canOfferQuarantine(ScanClassification.NO_KNOWN_THREAT, false))
    }

    @Test
    fun `an exact exclusion suppresses quarantine recommendation`() {
        assertFalse(QuarantinePolicy.canOfferQuarantine(ScanClassification.KNOWN_THREAT, true))
    }

    @Test
    fun `reviewable detections can be quarantined when not excluded`() {
        assertTrue(QuarantinePolicy.canOfferQuarantine(ScanClassification.UNKNOWN_APK, false))
        assertTrue(QuarantinePolicy.canOfferQuarantine(ScanClassification.SUSPICIOUS, false))
        assertTrue(QuarantinePolicy.canOfferQuarantine(ScanClassification.KNOWN_THREAT, false))
        assertTrue(QuarantinePolicy.canOfferQuarantine(ScanClassification.TEST_SIGNATURE, false))
    }

    @Test
    fun `automatic quarantine only applies to confirmed non-excluded threats`() {
        assertTrue(QuarantinePolicy.shouldAutoQuarantine(ScanClassification.KNOWN_THREAT, false))
        assertFalse(QuarantinePolicy.shouldAutoQuarantine(ScanClassification.KNOWN_THREAT, true))
        assertFalse(QuarantinePolicy.shouldAutoQuarantine(ScanClassification.SUSPICIOUS, false))
        assertFalse(QuarantinePolicy.shouldAutoQuarantine(ScanClassification.TEST_SIGNATURE, false))
        assertFalse(QuarantinePolicy.shouldAutoQuarantine(ScanClassification.UNKNOWN_APK, false))
    }
}
