package com.aman.security.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionPostureEvaluatorTest {
    @Test fun allEnabledVerifiedLayersReachStrong() {
        val result = ProtectionPostureEvaluator.evaluate(
            ProtectionPostureInput(
                databaseHealthy = true,
                freshSources = 5,
                totalSources = 5,
                backgroundProtectionEnabled = true,
                webGuardActive = true,
                devicePatchKnown = true,
                devicePatchCurrent = true,
                integrityStatus = AppIntegrityStatus.VERIFIED_RELEASE
            )
        )
        assertEquals(100, result.score)
        assertEquals(ProtectionPostureLevel.STRONG, result.level)
    }

    @Test fun signatureMismatchAlwaysLimitsReadiness() {
        val result = ProtectionPostureEvaluator.evaluate(
            ProtectionPostureInput(true, 5, 5, true, true, true, true, AppIntegrityStatus.SIGNATURE_MISMATCH)
        )
        assertEquals(ProtectionPostureLevel.LIMITED, result.level)
    }

    @Test fun debugBuildNeverReportsStrongProductionReadiness() {
        val result = ProtectionPostureEvaluator.evaluate(
            ProtectionPostureInput(true, 5, 5, true, true, true, true, AppIntegrityStatus.DEBUG_BUILD)
        )
        assertEquals(ProtectionPostureLevel.ATTENTION, result.level)
    }

    @Test fun disabledLayersDoNotLookFullyProtected() {
        val result = ProtectionPostureEvaluator.evaluate(
            ProtectionPostureInput(true, 1, 5, false, false, false, false, AppIntegrityStatus.DEBUG_BUILD)
        )
        assertTrue(result.score < 55)
        assertEquals(ProtectionPostureLevel.LIMITED, result.level)
    }
}
