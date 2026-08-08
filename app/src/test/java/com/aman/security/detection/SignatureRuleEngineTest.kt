package com.aman.security.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SignatureRuleEngineTest {
    @Test
    fun requiresAllMarkersAndAtLeastOneAnyMarker() {
        val rule = DetectionRule(
            id = "SPY_COMBO",
            family = ThreatFamily.SPYWARE,
            confidence = FindingConfidence.HIGH,
            weight = 42,
            allMarkers = setOf("SMS", "BOOT"),
            anyMarkers = setOf("CONTACTS", "MIC")
        )
        assertTrue(SignatureRuleEngine.match(setOf("SMS", "BOOT"), listOf(rule)).isEmpty())
        val matches = SignatureRuleEngine.match(setOf("SMS", "BOOT", "CONTACTS"), listOf(rule))
        assertEquals(1, matches.size)
        assertEquals(42, matches.single().score)
        assertEquals(ThreatFamily.SPYWARE, matches.single().family)
    }
}
