package com.aman.security.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Regression coverage for false positives seen on feature-rich legitimate apps. */
class BenignCapabilityRegressionTest {
    @Test
    fun stackedCapabilitiesAndLocalModelStayLowWithoutMalwareSpecificEvidence() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding("CHAT_PERMISSIONS", DetectionSource.MANIFEST, 26, FindingConfidence.MEDIUM, ThreatFamily.RISKWARE),
                DetectionFinding("AUDIO_LOCATION_BOOT", DetectionSource.STATIC_BEHAVIOR, 24, FindingConfidence.MEDIUM, ThreatFamily.STALKERWARE),
                DetectionFinding("PACKER", DetectionSource.PACKER, 16, FindingConfidence.MEDIUM, ThreatFamily.RISKWARE),
                DetectionFinding("LOCAL_MODEL", DetectionSource.LOCAL_MODEL, 20, FindingConfidence.HIGH, ThreatFamily.RISKWARE)
            )
        )

        assertTrue("benign capability stack reached ${verdict.level} (${verdict.score})", verdict.score < 20)
        assertEquals(DetectionVerdictLevel.LOW, verdict.level)
    }

    @Test
    fun independentMalwareSpecificCorroborationCanStillReachHigh() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding("ZERO_DAY_CHAIN", DetectionSource.ZERO_DAY_HEURISTIC, 32, FindingConfidence.HIGH, ThreatFamily.DROPPER),
                DetectionFinding("IMPERSONATION", DetectionSource.IMPERSONATION, 28, FindingConfidence.HIGH, ThreatFamily.DROPPER)
            )
        )

        assertTrue(verdict.score >= 55)
        assertTrue(verdict.level == DetectionVerdictLevel.HIGH || verdict.level == DetectionVerdictLevel.VERY_HIGH)
    }
}
