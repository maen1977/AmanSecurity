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
        assertTrue(result.score >= 55)
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
        assertTrue(result.score >= 55)
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
        assertTrue(result.score in 20..54)
    }

    @Test
    fun telephonyStateAndSmsAccessCombinationRaisesRisk() {
        val result = ApkRiskEvaluator.evaluate(
            setOf(ApkRiskSignal.TELEPHONY_STATE_API, ApkRiskSignal.SMS_ACCESS)
        )
        assertEquals(ApkRiskLevel.HIGH, result.level)
        assertTrue(result.score >= 55)
    }

    @Test
    fun isolatedBillingApiStaysLowRisk() {
        val result = ApkRiskEvaluator.evaluate(setOf(ApkRiskSignal.BILLING_API))
        assertEquals(ApkRiskLevel.LOW, result.level)
        assertEquals(8, result.score)
    }

    @Test
    fun billingApiCombinedWithAccessibilityBecomesSuspicious() {
        val result = ApkRiskEvaluator.evaluate(
            setOf(ApkRiskSignal.BILLING_API, ApkRiskSignal.ACCESSIBILITY_SERVICE)
        )
        assertEquals(ApkRiskLevel.HIGH, result.level)
        assertTrue(result.score >= 55)
    }

    @Test
    fun readPhoneStateAndContactsCombinationIsSuspicious() {
        val result = ApkRiskEvaluator.evaluate(
            setOf(ApkRiskSignal.READ_PHONE_STATE_API, ApkRiskSignal.CONTACTS_ACCESS)
        )
        assertEquals(ApkRiskLevel.HIGH, result.level)
        assertTrue(result.score >= 55)
    }

    @Test
    fun manageExternalStorageWithSensitivePermissionsIsSuspicious() {
        val result = ApkRiskEvaluator.evaluate(
            setOf(
                ApkRiskSignal.MANAGE_EXTERNAL_STORAGE_API,
                ApkRiskSignal.SMS_ACCESS,
                ApkRiskSignal.BOOT_START
            )
        )
        assertEquals(ApkRiskLevel.HIGH, result.level)
        assertTrue(result.score >= 55)
    }

    @Test
    fun isolatedReadPhoneStateStaysLowRisk() {
        val result = ApkRiskEvaluator.evaluate(setOf(ApkRiskSignal.READ_PHONE_STATE_API))
        assertEquals(ApkRiskLevel.LOW, result.level)
        assertEquals(6, result.score)
    }

    @Test
    fun isolatedManageExternalStorageStaysLowRisk() {
        val result = ApkRiskEvaluator.evaluate(setOf(ApkRiskSignal.MANAGE_EXTERNAL_STORAGE_API))
        assertEquals(ApkRiskLevel.LOW, result.level)
        assertEquals(6, result.score)
    }

    @Test
    fun isolatedTelephonyStateApiStaysLowRisk() {
        val result = ApkRiskEvaluator.evaluate(setOf(ApkRiskSignal.TELEPHONY_STATE_API))
        assertEquals(ApkRiskLevel.LOW, result.level)
        assertEquals(6, result.score)
    }
}
