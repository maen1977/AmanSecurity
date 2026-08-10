package com.aman.security.detection

import org.junit.Assert.assertTrue
import org.junit.Test

class FalsePositiveStressTest {
    @Test fun singleLegitimateCapabilitiesNeverReachHigh() {
        val cases = listOf(
            DetectionFinding("CAMERA", DetectionSource.MANIFEST, 12, FindingConfidence.LOW, ThreatFamily.RISKWARE),
            DetectionFinding("LOCATION", DetectionSource.MANIFEST, 12, FindingConfidence.LOW, ThreatFamily.RISKWARE),
            DetectionFinding("MIC", DetectionSource.MANIFEST, 12, FindingConfidence.LOW, ThreatFamily.RISKWARE),
            DetectionFinding("NATIVE", DetectionSource.DEX, 16, FindingConfidence.LOW, ThreatFamily.RISKWARE),
            DetectionFinding("REFLECTION", DetectionSource.PACKER, 22, FindingConfidence.LOW, ThreatFamily.RISKWARE),
            DetectionFinding("CLIPBOARD", DetectionSource.DEX, 18, FindingConfidence.LOW, ThreatFamily.RISKWARE)
        )
        cases.forEach { finding ->
            val verdict = VerdictEngine.evaluate(listOf(finding))
            assertTrue("${finding.id} unexpectedly reached ${verdict.level}", verdict.level != DetectionVerdictLevel.HIGH && verdict.level != DetectionVerdictLevel.VERY_HIGH)
        }
    }

    @Test fun twoMediumGenericSignalsStayBelowHighWithoutStrongEvidence() {
        val verdict = VerdictEngine.evaluate(listOf(
            DetectionFinding("GENERIC_NETWORK", DetectionSource.NETWORK, 18, FindingConfidence.MEDIUM, ThreatFamily.RISKWARE),
            DetectionFinding("GENERIC_PACKER", DetectionSource.PACKER, 18, FindingConfidence.MEDIUM, ThreatFamily.RISKWARE)
        ))
        assertTrue(verdict.score < 55)
    }

    @Test fun exactAllowlistStillCapsMultiEngineHeuristics() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding("RULE", DetectionSource.SIGNATURE_RULE, 35, FindingConfidence.HIGH, ThreatFamily.RISKWARE),
                DetectionFinding("DEX", DetectionSource.DEX, 30, FindingConfidence.HIGH, ThreatFamily.RISKWARE),
                DetectionFinding("NETWORK", DetectionSource.NETWORK, 25, FindingConfidence.HIGH, ThreatFamily.RISKWARE)
            ),
            allowlisted = true
        )
        assertTrue(verdict.score <= 19)
        assertTrue(verdict.level == DetectionVerdictLevel.LOW)
    }
}
