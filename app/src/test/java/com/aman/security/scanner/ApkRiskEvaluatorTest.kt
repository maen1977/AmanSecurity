package com.aman.security.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkRiskEvaluatorTest {
    @Test
    fun isolatedCameraPermissionStaysLow() {
        val result = ApkRiskEvaluator.evaluate(setOf(ApkRiskSignal.CAMERA))
        assertEquals(ApkRiskLevel.LOW, result.level)
        assertEquals(4, result.score)
    }

    @Test
    fun accessibilityAndOverlayCombinationIsHighRisk() {
        val result = ApkRiskEvaluator.evaluate(
            setOf(ApkRiskSignal.ACCESSIBILITY_SERVICE, ApkRiskSignal.OVERLAY_PERMISSION)
        )
        assertEquals(ApkRiskLevel.HIGH, result.level)
        assertTrue(result.score >= 45)
    }

    @Test
    fun spywareLikeSmsContactsBootCombinationIsHighRisk() {
        val result = ApkRiskEvaluator.evaluate(
            setOf(
                ApkRiskSignal.SMS_ACCESS,
                ApkRiskSignal.CONTACTS_ACCESS,
                ApkRiskSignal.BOOT_START,
                ApkRiskSignal.SMS_API,
                ApkRiskSignal.DEVICE_IDENTIFIER_API
            )
        )
        assertEquals(ApkRiskLevel.HIGH, result.level)
        assertTrue(result.score >= 45)
    }

    @Test
    fun nativeCodeAloneDoesNotBecomeSuspicious() {
        val result = ApkRiskEvaluator.evaluate(setOf(ApkRiskSignal.NATIVE_CODE))
        assertEquals(ApkRiskLevel.LOW, result.level)
        assertEquals(2, result.score)
    }

    @Test
    fun dynamicLoadingAndRuntimeExecutionNeedReviewButNotAutomaticMalwareVerdict() {
        val result = ApkRiskEvaluator.evaluate(
            setOf(ApkRiskSignal.DYNAMIC_CODE_LOADING, ApkRiskSignal.RUNTIME_EXECUTION)
        )
        assertEquals(ApkRiskLevel.REVIEW, result.level)
        assertTrue(result.score in 20..44)
    }
}
