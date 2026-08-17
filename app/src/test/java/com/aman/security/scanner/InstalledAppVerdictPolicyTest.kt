package com.aman.security.scanner

import com.aman.security.detection.DetectionVerdictLevel
import org.junit.Assert.assertEquals
import org.junit.Test

class InstalledAppVerdictPolicyTest {
    @Test
    fun heuristic_levels_are_review_not_red_threats() {
        assertEquals(AppRiskLevel.MEDIUM, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.VERY_HIGH))
        assertEquals(AppRiskLevel.MEDIUM, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.HIGH))
        assertEquals(AppRiskLevel.MEDIUM, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.REVIEW))
    }

    @Test
    fun confirmed_identity_is_the_only_red_installed_app_level() {
        assertEquals(AppRiskLevel.KNOWN_THREAT, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.KNOWN_THREAT))
        assertEquals(AppRiskLevel.LOW, InstalledAppVerdictPolicy.riskLevel(DetectionVerdictLevel.LOW))
    }
}

