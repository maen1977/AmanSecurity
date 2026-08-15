package com.aman.security.security

import org.junit.Assert.assertEquals
import org.junit.Test

class ProtectionReadinessEvaluatorTest {
    @Test fun allLocalChecksReadyReportsReady() {
        val result = ProtectionReadinessEvaluator.evaluate(
            ProtectionReadinessInput(
                databaseHealthy = true,
                serviceHealthy = true,
                appInstallMonitorEnabled = true,
                downloadsProtectionReady = true,
                webProtectionActive = true,
                webProtectionVerified = true,
                intrusionCheckReady = true,
                dataExfiltrationCheckReady = true
            )
        )
        assertEquals(8, result.readyChecks)
        assertEquals(8, result.totalChecks)
        assertEquals(ProtectionReadinessLevel.READY, result.level)
    }

    @Test fun unverifiedWebLayerNeedsAttentionEvenWhenOtherChecksPass() {
        val result = ProtectionReadinessEvaluator.evaluate(
            ProtectionReadinessInput(
                databaseHealthy = true,
                serviceHealthy = true,
                appInstallMonitorEnabled = true,
                downloadsProtectionReady = true,
                webProtectionActive = true,
                webProtectionVerified = false,
                intrusionCheckReady = true,
                dataExfiltrationCheckReady = true
            )
        )
        assertEquals(7, result.readyChecks)
        assertEquals(ProtectionReadinessLevel.ATTENTION, result.level)
    }

    @Test fun serviceFailureLimitsReadiness() {
        val result = ProtectionReadinessEvaluator.evaluate(
            ProtectionReadinessInput(
                databaseHealthy = true,
                serviceHealthy = false,
                appInstallMonitorEnabled = false,
                downloadsProtectionReady = false,
                webProtectionActive = false,
                webProtectionVerified = true,
                intrusionCheckReady = false,
                dataExfiltrationCheckReady = false
            )
        )
        assertEquals(2, result.readyChecks)
        assertEquals(ProtectionReadinessLevel.LIMITED, result.level)
    }
}

