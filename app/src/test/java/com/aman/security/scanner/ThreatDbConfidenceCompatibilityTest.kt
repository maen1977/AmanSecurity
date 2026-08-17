package com.aman.security.scanner

import com.aman.security.detection.FindingConfidence
import org.junit.Assert.assertEquals
import org.junit.Test

class ThreatDbConfidenceCompatibilityTest {
    @Test
    fun criticalConfidenceIsParsedFromDetectionRules() {
        val csv = "RULE|CRITICAL_TEST|MALWARE|CRITICAL|90|MALWARE_MARKER|"

        val ruleset = ThreatDbValidator.parseDetectionRules(csv.toByteArray(), expectedCount = 1)

        assertEquals(FindingConfidence.CRITICAL, ruleset.rules.single().confidence)
    }

    @Test
    fun futureConfidenceValueFallsBackWithoutCrashing() {
        val csv = "RULE|FUTURE_CONFIDENCE_TEST|MALWARE|FUTURE_LEVEL|20|FUTURE_MARKER|"

        val ruleset = ThreatDbValidator.parseDetectionRules(csv.toByteArray(), expectedCount = 1)

        assertEquals(FindingConfidence.UNKNOWN, ruleset.rules.single().confidence)
    }
}

