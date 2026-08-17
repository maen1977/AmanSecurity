package com.aman.security.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Regression coverage for installed apps with legitimate sensitive capabilities. */
class InstalledAppReasoningRegressionTest {
    @Test
    fun installedAppReasoningIsReviewOnlyWithoutMalwareSpecificEvidence() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding(
                    id = "INSTALLED_APP_REASONING_REVIEW",
                    source = DetectionSource.LOCAL_MODEL,
                    score = 10,
                    confidence = FindingConfidence.MEDIUM,
                    family = ThreatFamily.RISKWARE,
                    reference = "INSTALLED_APP_REASONING_REVIEW"
                )
            )
        )

        assertTrue("generic installed-app reasoning reached ${verdict.level} (${verdict.score})", verdict.score < 20)
        assertEquals(DetectionVerdictLevel.LOW, verdict.level)
    }
}

