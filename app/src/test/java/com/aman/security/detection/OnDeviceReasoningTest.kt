package com.aman.security.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the 6.0.0 on-device reasoning layer:
 * LocalReasoningClassifier, ReasoningDecisionEngine, AppRelationshipGraph.
 */
class OnDeviceReasoningTest {

    private val weights = mapOf(
        "bias" to -12.18811,
        "surveillance" to 8.759431,
        "stealth" to 9.482711,
        "exfiltration" to 11.352311,
        "persistence" to 12.98776,
        "monetization" to 12.40152,
        "privilege" to 7.873656,
        "anti_analysis" to 10.781444,
        "impersonation" to 13.043453
    )

    @Test
    fun reasoningClassifier_confirms_fullly_malicious_profile() {
        val classifier = LocalReasoningClassifier(weights)
        val result = classifier.reason(
            mapOf(
                "surveillance" to 1.0,
                "stealth" to 1.0,
                "exfiltration" to 1.0,
                "persistence" to 1.0,
                "anti_analysis" to 1.0
            )
        )
        assertNotNull(result.finding)
        assertTrue("probability=${result.probability}", result.probability >= 0.92)
        assertEquals(FindingConfidence.CONFIRMED, result.finding!!.confidence)
        assertEquals(30, result.finding!!.score)
    }

    @Test
    fun reasoningClassifier_returns_high_on_partial_malicious_shape() {
        val classifier = LocalReasoningClassifier(weights)
        val result = classifier.reason(
            mapOf(
                "surveillance" to 1.0,
                "exfiltration" to 1.0,
                "persistence" to 1.0
            )
        )
        assertNotNull(result.finding)
        assertTrue("probability=${result.probability}", result.probability >= 0.92)
        assertEquals(FindingConfidence.CONFIRMED, result.finding!!.confidence)
    }

    @Test
    fun reasoningClassifier_returns_review_on_mild_shape() {
        val classifier = LocalReasoningClassifier(weights)
        val result = classifier.reason(mapOf("surveillance" to 0.6, "stealth" to 0.5, "privilege" to 0.5))
        assertNotNull(result.finding)
        assertTrue("probability=${result.probability}", result.probability in 0.65..0.92)
        assertNotNull(result.finding!!.id.startsWith("REASONING_AI_"))
        assertTrue(result.topContributors.isNotEmpty())
    }

    @Test
    fun reasoningClassifier_stays_silent_on_benign_profile() {
        val classifier = LocalReasoningClassifier(weights)
        val result = classifier.reason(emptyMap())
        assertNull(result.finding)
        assertTrue("probability=${result.probability}", result.probability < 0.65)
        assertTrue(result.topContributors.isEmpty())
    }

    @Test
    fun reasoningClassifier_stays_silent_on_single_weak_signal() {
        val classifier = LocalReasoningClassifier(weights)
        val result = classifier.reason(mapOf("privilege" to 0.5))
        assertNull(result.finding)
        assertTrue("probability=${result.probability}", result.probability < 0.65)
    }

    @Test
    fun reasoningClassifier_explains_top_contributors() {
        val classifier = LocalReasoningClassifier(weights)
        val result = classifier.reason(
            mapOf("surveillance" to 1.0, "stealth" to 1.0, "exfiltration" to 1.0)
        )
        assertEquals(3, result.topContributors.size)
        assertTrue(result.topContributors.all { it.second > 0 })
        assertEquals("exfiltration", result.topContributors.first().first)
    }

    @Test
    fun reasoningDecisionEngine_empty_findings_is_safe_with_decision_chain() {
        val verdict = ReasoningDecisionEngine.decide(emptyList())
        assertEquals(DetectionVerdictLevel.LOW, verdict.level)
        assertEquals("decision_safe", verdict.explanationKey)
        assertEquals(0, verdict.score)
    }

    @Test
    fun reasoningDecisionEngine_fuses_confirmed_evidence_to_known_threat() {
        val findings = listOf(
            DetectionFinding(
                "SIG-1", DetectionSource.SIGNATURE_RULE, 100,
                FindingConfidence.CONFIRMED, ThreatFamily.MALWARE
            )
        )
        val verdict = ReasoningDecisionEngine.decide(findings)
        assertEquals(DetectionVerdictLevel.KNOWN_THREAT, verdict.level)
        assertEquals(FindingConfidence.CONFIRMED, verdict.confidence)
        assertEquals("explanation_malware_confirmed", verdict.explanationKey)
        assertTrue(verdict.reasoningChain.contains("step_confirmed_evidence"))
        assertTrue(verdict.reasoningChain.contains("step_evidence_fusion"))
        assertTrue(verdict.reasoningChain.contains("step_final_verdict"))
    }

    @Test
    fun reasoningDecisionEngine_cross_engine_corroboration_does_not_confirm_local_model() {
        val findings = listOf(
            DetectionFinding("A", DetectionSource.SIGNATURE_RULE, 60, FindingConfidence.HIGH, ThreatFamily.SPYWARE),
            DetectionFinding("B", DetectionSource.STATIC_BEHAVIOR, 50, FindingConfidence.HIGH, ThreatFamily.SPYWARE),
            DetectionFinding("C", DetectionSource.LOCAL_MODEL, 30, FindingConfidence.CONFIRMED, ThreatFamily.SPYWARE)
        )
        val verdict = ReasoningDecisionEngine.decide(findings)
        assertEquals(DetectionVerdictLevel.VERY_HIGH, verdict.level)
        assertTrue(verdict.reasoningChain.contains("step_cross_engine_corroboration"))
        assertTrue(!verdict.reasoningChain.contains("step_confirmed_evidence"))
        assertEquals(ThreatFamily.SPYWARE, verdict.family)
    }

    @Test
    fun reasoningDecisionEngine_review_level_for_mild_fused_score() {
        val findings = listOf(
            DetectionFinding("M", DetectionSource.LOCAL_MODEL, 15, FindingConfidence.HIGH, ThreatFamily.RISKWARE),
            DetectionFinding("N", DetectionSource.MANIFEST, 10, FindingConfidence.MEDIUM, ThreatFamily.RISKWARE)
        )
        val verdict = ReasoningDecisionEngine.decide(findings)
        assertEquals(DetectionVerdictLevel.REVIEW, verdict.level)
        assertTrue(verdict.reasoningChain.contains("step_evidence_fusion"))
    }

    @Test
    fun reasoningDecisionEngine_blacklist_reference_adds_chain_step() {
        val findings = listOf(
            DetectionFinding("REF-1", DetectionSource.REPUTATION, 100, FindingConfidence.CONFIRMED, ThreatFamily.BANKER, reference = "REF-1")
        )
        val verdict = ReasoningDecisionEngine.decide(findings, confirmedReference = true)
        assertEquals(DetectionVerdictLevel.KNOWN_THREAT, verdict.level)
        assertTrue(verdict.reasoningChain.contains("step_reference_blacklist"))
    }

    @Test
    fun appRelationshipGraph_raises_mosaic_when_capabilities_spread_across_apps() {
        val graph = AppRelationshipGraph()
        graph.observe("a.reader", setOf("SMS_READ", "ACCESSIBILITY"))
        graph.observe("a.recorder", setOf("AUDIO_RECORD", "INPUT_METHOD"))
        graph.observe("a.viewer", setOf("OVERLAY", "LOCATION"))
        val alerts = graph.analyze()
        val mosaic = alerts.firstOrNull { it.signal == "SURVEILLANCE_MOSAIC" }
        assertNotNull(mosaic)
        assertEquals(FindingConfidence.HIGH, mosaic!!.severity)
        assertEquals(40, mosaic.score)
        assertEquals(3, mosaic.involvedApps.size)
    }

    @Test
    fun appRelationshipGraph_stays_silent_when_only_one_app_observed() {
        val graph = AppRelationshipGraph()
        graph.observe("a.reader", setOf("SMS_READ"))
        val alerts = graph.analyze()
        assertNull(alerts.firstOrNull { it.signal == "SURVEILLANCE_MOSAIC" })
    }

    @Test
    fun appRelationshipGraph_flags_concentrated_watcher() {
        val graph = AppRelationshipGraph()
        graph.observe("a.boss", setOf("SMS_READ", "AUDIO_RECORD", "ACCESSIBILITY", "OVERLAY"))
        val alerts = graph.analyze()
        val watcher = alerts.firstOrNull { it.signal == "CONCENTRATED_WATCHER" }
        assertNotNull(watcher)
        assertEquals(FindingConfidence.HIGH, watcher!!.severity)
        assertEquals(setOf("a.boss"), watcher.involvedApps)
    }

    @Test
    fun appRelationshipGraph_ignores_empty_observation() {
        val graph = AppRelationshipGraph()
        graph.observe("a.clean", emptySet())
        assertEquals(0, graph.analyze().size)
        assertEquals(0, graph.size())
    }

    @Test
    fun appRelationshipGraph_reports_all_three_mosaic_classes_with_full_coverage() {
        val graph = AppRelationshipGraph()
        graph.observe("a1", setOf("SMS_READ", "INPUT_METHOD", "CAMERA", "MICROPHONE", "BILLING", "CALL_LOG"))
        graph.observe("a2", setOf("AUDIO_RECORD", "ACCESSIBILITY", "LOCATION", "CONTACTS", "QUERY_ALL_PACKAGES", "BOOT_PERSISTENCE"))
        graph.observe("a3", setOf("OVERLAY", "MEDIA_READ"))
        val alerts = graph.analyze()
        val signals = alerts.map { it.signal }.toSet()
        assertTrue(signals.contains("SURVEILLANCE_MOSAIC"))
        assertTrue(signals.contains("PRIVACY_MOSAIC"))
        assertTrue(signals.contains("TELEMETRY_MOSAIC"))
    }

    @Test
    fun reasoningWeights_bounds_are_respected_by_validator_constants() {
        // The production ThreatDbValidator requires each REASONING weight in -20..20.
        weights.forEach { (key, value) ->
            assertTrue("weight $key=$value out of validator bounds", value in -20.0..20.0)
        }
        assertFalse(weights.containsKey("unknown_dimension"))
    }
}
