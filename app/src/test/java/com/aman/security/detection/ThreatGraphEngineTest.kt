package com.aman.security.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatGraphEngineTest {
    @Test
    fun reviewedGraphLinkOnlyCorroboratesAndNeverConfirms() {
        val findings = listOf(
            DetectionFinding("SEED", DetectionSource.STATIC_BEHAVIOR, 25, FindingConfidence.HIGH, ThreatFamily.SPYWARE, "SEED")
        )
        val links = listOf(
            ThreatGraphLink("SEED", "RELATED", ThreatGraphRelation.SAME_CAMPAIGN, FindingConfidence.CONFIRMED, 24)
        )
        val out = ThreatGraphEngine.correlate(findings, links)
        assertEquals(1, out.size)
        assertEquals(DetectionSource.THREAT_GRAPH, out.first().source)
        assertEquals(FindingConfidence.HIGH, out.first().confidence)
        assertTrue(out.first().score <= 24)
    }

    @Test
    fun graphDoesNotPropagateFromTestOrWeakNoise() {
        val links = listOf(
            ThreatGraphLink("TEST", "RELATED", ThreatGraphRelation.REVIEWED_ASSOCIATION, FindingConfidence.HIGH, 20)
        )
        val test = DetectionFinding("TEST", DetectionSource.REPUTATION, 0, FindingConfidence.CONFIRMED, ThreatFamily.TEST, "TEST")
        val weak = DetectionFinding("TEST", DetectionSource.PACKER, 5, FindingConfidence.LOW, ThreatFamily.RISKWARE, "TEST")
        assertTrue(ThreatGraphEngine.correlate(listOf(test), links).isEmpty())
        assertTrue(ThreatGraphEngine.correlate(listOf(weak), links).isEmpty())
    }
}
