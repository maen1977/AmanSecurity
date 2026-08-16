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
        assertEquals(52, matches.single().score)
        assertEquals(ThreatFamily.SPYWARE, matches.single().family)
    }

    @Test
    fun notMarkersSuppressRuleForTrustedPlatforms() {
        val rule = DetectionRule(
            id = "SPY_COMBO",
            family = ThreatFamily.SPYWARE,
            confidence = FindingConfidence.HIGH,
            weight = 42,
            allMarkers = setOf("SMS", "BOOT"),
            anyMarkers = setOf("CONTACTS"),
            notMarkers = setOf("GOOGLE_PLATFORM", "BANK_SIGNATURE")
        )
        // Rule matches, but a trusted not-marker vetoes it.
        assertTrue(SignatureRuleEngine.match(setOf("SMS", "BOOT", "CONTACTS", "GOOGLE_PLATFORM"), listOf(rule)).isEmpty())
        // Without the veto marker the rule fires with its original weight.
        val matches = SignatureRuleEngine.match(setOf("SMS", "BOOT", "CONTACTS"), listOf(rule))
        assertEquals(52, matches.single().score)
    }

    @Test
    fun multiMatchBoostsScoreWhenMostMarkersAreCovered() {
        val rule = DetectionRule(
            id = "BANK_HEIST",
            family = ThreatFamily.BANKER,
            confidence = FindingConfidence.HIGH,
            weight = 60,
            allMarkers = setOf("SMS", "BOOT", "CALL"),
            anyMarkers = setOf("CONTACTS", "MIC", "CAMERA", "LOCATION", "OVERLAY", "INSTALL_PACKAGES")
        )
        // Covers all 9 markers -> boosted (60 * 1.25 = 75).
        val boosted = SignatureRuleEngine.match(
            setOf("SMS", "BOOT", "CALL", "CONTACTS", "MIC", "CAMERA", "LOCATION", "OVERLAY", "INSTALL_PACKAGES"),
            listOf(rule)
        )
        assertEquals(75, boosted.single().score)
        // Covers 4 of 9 markers -> no boost because 4*2 is not strictly greater than 9.
        val partial = SignatureRuleEngine.match(setOf("SMS", "BOOT", "CALL", "MIC"), listOf(rule))
        assertEquals(60, partial.single().score)
    }
}
