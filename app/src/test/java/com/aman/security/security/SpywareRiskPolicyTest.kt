package com.aman.security.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SpywareRiskPolicyTest {
    @Test
    fun ordinaryMessagingPermissionsDoNotBecomeSpyware() {
        val result = SpywareRiskPolicy.evaluate(
            setOf(
                SpywareCapabilitySignal.MICROPHONE_ACCESS,
                SpywareCapabilitySignal.LOCATION_ACCESS,
                SpywareCapabilitySignal.CONTACTS_ACCESS,
                SpywareCapabilitySignal.BOOT_PERSISTENCE
            )
        )
        assertEquals(SpywareReviewLevel.LOW, result.level)
        assertTrue(result.score < 30)
    }

    @Test
    fun sideloadedPrivilegedSurveillanceCombinationEscalates() {
        val result = SpywareRiskPolicy.evaluate(
            setOf(
                SpywareCapabilitySignal.ACCESSIBILITY_SERVICE,
                SpywareCapabilitySignal.ACCESSIBILITY_ACTIVE,
                SpywareCapabilitySignal.SIDELOADED,
                SpywareCapabilitySignal.BOOT_PERSISTENCE,
                SpywareCapabilitySignal.MICROPHONE_ACCESS,
                SpywareCapabilitySignal.LOCATION_ACCESS
            )
        )
        assertEquals(SpywareReviewLevel.HIGH, result.level)
        assertTrue(result.score >= 40)
    }

    @Test
    fun declaredPrivilegedServiceWithoutActivationStaysReviewOnly() {
        val result = SpywareRiskPolicy.evaluate(
            setOf(
                SpywareCapabilitySignal.ACCESSIBILITY_SERVICE,
                SpywareCapabilitySignal.SIDELOADED,
                SpywareCapabilitySignal.MICROPHONE_ACCESS
            )
        )
        assertEquals(SpywareReviewLevel.REVIEW, result.level)
        assertTrue(result.score < 65)
    }

    @Test
    fun sideloadedSensitivePermissionClusterNeedsReview() {
        val result = SpywareRiskPolicy.evaluate(
            setOf(
                SpywareCapabilitySignal.SIDELOADED,
                SpywareCapabilitySignal.SENSITIVE_PERMISSION_CLUSTER,
                SpywareCapabilitySignal.MICROPHONE_ACCESS,
                SpywareCapabilitySignal.CAMERA_ACCESS,
                SpywareCapabilitySignal.LOCATION_ACCESS
            )
        )

        assertEquals(SpywareReviewLevel.REVIEW, result.level)
        assertTrue(result.score >= 35)
        assertTrue(SpywareCapabilitySignal.SENSITIVE_PERMISSION_CLUSTER in result.signals)
    }

    @Test
    fun permissionsAloneNeverEscalateToReview() {
        val result = SpywareRiskPolicy.evaluate(
            setOf(
                SpywareCapabilitySignal.SMS_ACCESS,
                SpywareCapabilitySignal.CALL_LOG_ACCESS,
                SpywareCapabilitySignal.LOCATION_ACCESS,
                SpywareCapabilitySignal.MICROPHONE_ACCESS,
                SpywareCapabilitySignal.CONTACTS_ACCESS
            )
        )
        assertEquals(SpywareReviewLevel.LOW, result.level)
        assertTrue(result.score < 30)
    }
}
