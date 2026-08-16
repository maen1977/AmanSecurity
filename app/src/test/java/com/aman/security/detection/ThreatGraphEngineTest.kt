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

    @Test
    fun clusterPromotesConvergedCorroborationToHigh() {
        val findings = listOf(
            DetectionFinding("SEED_A", DetectionSource.STATIC_BEHAVIOR, 25, FindingConfidence.HIGH, ThreatFamily.SPYWARE, "SEED_A"),
            DetectionFinding("SEED_B", DetectionSource.ZERO_DAY_HEURISTIC, 30, FindingConfidence.MEDIUM, ThreatFamily.SPYWARE, "SEED_B")
        )
        val links = listOf(
            ThreatGraphLink("SEED_A", "C2_HOST", ThreatGraphRelation.CONTACTS_HOST, FindingConfidence.HIGH, 20),
            ThreatGraphLink("SEED_B", "C2_HOST", ThreatGraphRelation.SAME_CAMPAIGN, FindingConfidence.MEDIUM, 18)
        )
        val out = ThreatGraphEngine.correlate(findings, links)
        assertEquals(3, out.size)
        val cluster = out.first { it.id == "GRAPH_CLUSTER_C2_HOST" }
        assertEquals(24, cluster.score)
        assertEquals(FindingConfidence.HIGH, cluster.confidence)
    }

    @Test
    fun clusterNeverMergesMixedFamilies() {
        val findings = listOf(
            DetectionFinding("SEED_A", DetectionSource.STATIC_BEHAVIOR, 25, FindingConfidence.HIGH, ThreatFamily.SPYWARE, "SEED_A"),
            DetectionFinding("SEED_B", DetectionSource.ZERO_DAY_HEURISTIC, 30, FindingConfidence.MEDIUM, ThreatFamily.ADWARE, "SEED_B")
        )
        val links = listOf(
            ThreatGraphLink("SEED_A", "HOST_X", ThreatGraphRelation.CONTACTS_HOST, FindingConfidence.HIGH, 20),
            ThreatGraphLink("SEED_B", "HOST_X", ThreatGraphRelation.SAME_CAMPAIGN, FindingConfidence.MEDIUM, 18)
        )
        val out = ThreatGraphEngine.correlate(findings, links)
        assertTrue("mixed families must not create a cluster", out.none { it.id == "GRAPH_CLUSTER_HOST_X" })
        assertEquals(2, out.size)
    }
}
