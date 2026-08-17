package com.aman.security.scanner

import com.aman.security.detection.DetectionFinding
import com.aman.security.detection.DetectionSource
import com.aman.security.detection.DetectionVerdictLevel
import com.aman.security.detection.FindingConfidence
import com.aman.security.detection.MultiEngineVerdict
import com.aman.security.detection.ThreatFamily
import org.junit.Assert.assertEquals
import org.junit.Test

class InstalledAppVerdictPolicyTest {
    @Test
    fun weakReviewScore49_isNotShownAsInstalledAppReview() {
        val verdict = verdict(score = 49, level = DetectionVerdictLevel.REVIEW)

        assertEquals(AppRiskLevel.LOW, InstalledAppVerdictPolicy.riskLevel(verdict))
    }

    @Test
    fun strongerReviewScore55_remainsVisibleForInspection() {
        val verdict = verdict(score = 55, level = DetectionVerdictLevel.REVIEW)

        assertEquals(AppRiskLevel.MEDIUM, InstalledAppVerdictPolicy.riskLevel(verdict))
    }

    @Test
    fun heuristicLevels_areReviewNotRedThreats() {
        assertEquals(AppRiskLevel.MEDIUM, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.VERY_HIGH))
        assertEquals(AppRiskLevel.MEDIUM, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.HIGH))
        assertEquals(AppRiskLevel.MEDIUM, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.REVIEW))
    }

    @Test
    fun confirmedIdentity_isTheOnlyRedInstalledAppLevel() {
        assertEquals(AppRiskLevel.KNOWN_THREAT, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.KNOWN_THREAT))
        assertEquals(AppRiskLevel.LOW, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.LOW))
        assertEquals(
            AppRiskLevel.KNOWN_THREAT,
            InstalledAppVerdictPolicy.riskLevel(verdict(score = 100, level = DetectionVerdictLevel.KNOWN_THREAT))
        )
    }

    private fun verdict(score: Int, level: DetectionVerdictLevel): MultiEngineVerdict = MultiEngineVerdict(
        score = score,
        level = level,
        family = ThreatFamily.RISKWARE,
        confidence = FindingConfidence.MEDIUM,
        findings = listOf(
            DetectionFinding(
                id = "TEST_REVIEW",
                source = DetectionSource.MANIFEST,
                score = score,
                confidence = FindingConfidence.MEDIUM,
                family = ThreatFamily.RISKWARE
            )
        ),
        engineCount = 1
    )
}
