package com.aman.security.security

import org.junit.Assert.assertEquals
import org.junit.Test

class SpywareRiskPolicyTest {
    @Test
    fun ordinaryPermissionsStayLow() {
        val assessment = SpywareRiskPolicy.evaluate(setOf(SpywareCapabilitySignal.MICROPHONE_ACCESS, SpywareCapabilitySignal.LOCATION_ACCESS))
        assertEquals(SpywareReviewLevel.LOW, assessment.level)
        assertEquals(29.coerceAtMost(assessment.score), assessment.score)
    }

    @Test
    fun keyloggerInputMethodEscalatesReview() {
        val assessment = SpywareRiskPolicy.evaluate(setOf(SpywareCapabilitySignal.INPUT_METHOD_SERVICE, SpywareCapabilitySignal.MICROPHONE_ACCESS, SpywareCapabilitySignal.SMS_ACCESS))
        assertEquals(SpywareReviewLevel.REVIEW, assessment.level)
    }

    @Test
    fun surveillanceComboTriggersReview() {
        val signals = setOf(
            SpywareCapabilitySignal.CAMERA_ACCESS, SpywareCapabilitySignal.MICROPHONE_ACCESS,
            SpywareCapabilitySignal.LOCATION_ACCESS, SpywareCapabilitySignal.SMS_ACCESS
        )
        val assessment = SpywareRiskPolicy.evaluate(signals + SpywareCapabilitySignal.BOOT_PERSISTENCE)
        assertEquals(SpywareReviewLevel.REVIEW, assessment.level)
    }

    @Test
    fun heavySurveillanceWithPersistenceIsHighRisk() {
        val signals = setOf(
            SpywareCapabilitySignal.SMS_ACCESS, SpywareCapabilitySignal.CALL_LOG_ACCESS,
            SpywareCapabilitySignal.LOCATION_ACCESS, SpywareCapabilitySignal.MICROPHONE_ACCESS,
            SpywareCapabilitySignal.CONTACTS_ACCESS, SpywareCapabilitySignal.BOOT_PERSISTENCE
        )
        val assessment = SpywareRiskPolicy.evaluate(signals)
        assertEquals(SpywareReviewLevel.HIGH, assessment.level)
    }

    @Test
    fun stalkerwareFullChainIsHighRisk() {
        val signals = setOf(
            SpywareCapabilitySignal.ACCESSIBILITY_SERVICE, SpywareCapabilitySignal.ACCESSIBILITY_ACTIVE,
            SpywareCapabilitySignal.SMS_ACCESS, SpywareCapabilitySignal.CALL_LOG_ACCESS,
            SpywareCapabilitySignal.LOCATION_ACCESS, SpywareCapabilitySignal.BOOT_PERSISTENCE,
            SpywareCapabilitySignal.SIDELOADED
        )
        val assessment = SpywareRiskPolicy.evaluate(signals)
        assertEquals(SpywareReviewLevel.HIGH, assessment.level)
        assertEquals(65.coerceAtLeast(assessment.score), assessment.score)
    }
}
