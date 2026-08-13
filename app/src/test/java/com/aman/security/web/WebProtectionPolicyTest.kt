package com.aman.security.web

import com.aman.security.scanner.UrlRiskLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WebProtectionPolicyTest {
    @Test fun knownThreatsAreBlocked() {
        assertEquals(WebProtectionDecision.BLOCK, WebProtectionPolicy.decide(UrlRiskLevel.KNOWN_PHISHING))
        assertEquals(WebProtectionDecision.BLOCK, WebProtectionPolicy.decide(UrlRiskLevel.KNOWN_MALICIOUS))
        assertFalse(WebProtectionPolicy.mayOpenAfterWarning(UrlRiskLevel.KNOWN_MALICIOUS))
    }

    @Test fun heuristicsRequireExplicitWarning() {
        assertEquals(WebProtectionDecision.CAUTION, WebProtectionPolicy.decide(UrlRiskLevel.REVIEW))
        assertEquals(WebProtectionDecision.CAUTION, WebProtectionPolicy.decide(UrlRiskLevel.HIGH))
        assertTrue(WebProtectionPolicy.mayOpenAfterWarning(UrlRiskLevel.HIGH))
    }

    @Test fun harmlessTestSignaturesAreStoppedWithoutBeingMalware() {
        assertEquals(WebProtectionDecision.TEST, WebProtectionPolicy.decide(UrlRiskLevel.TEST_SIGNATURE))
        assertFalse(WebProtectionPolicy.mayOpenAfterWarning(UrlRiskLevel.TEST_SIGNATURE))
    }

    @Test fun lowRiskCanBeForwarded() {
        assertEquals(WebProtectionDecision.ALLOW, WebProtectionPolicy.decide(UrlRiskLevel.LOW))
    }
}
