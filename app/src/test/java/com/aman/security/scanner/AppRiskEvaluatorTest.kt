package com.aman.security.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRiskEvaluatorTest {
    @Test
    fun cleanStoreAppStaysLow() {
        val result = AppRiskEvaluator.evaluate(
            AppRiskInput(
                requestedPermissions = emptySet(),
                hasAccessibilityService = false,
                installSource = AppInstallSource.STORE
            )
        )
        assertEquals(0, result.score)
        assertEquals(AppRiskLevel.LOW, result.level)
        assertTrue(result.signals.isEmpty())
    }

    @Test
    fun isolatedCameraPermissionDoesNotBecomeHighRisk() {
        val result = AppRiskEvaluator.evaluate(
            AppRiskInput(
                requestedPermissions = setOf("android.permission.CAMERA"),
                hasAccessibilityService = false,
                installSource = AppInstallSource.STORE
            )
        )
        assertEquals(AppRiskLevel.LOW, result.level)
        assertEquals(4, result.score)
    }

    @Test
    fun accessibilityAndOverlayCombinationIsHighRiskIndicator() {
        val result = AppRiskEvaluator.evaluate(
            AppRiskInput(
                requestedPermissions = setOf("android.permission.SYSTEM_ALERT_WINDOW"),
                hasAccessibilityService = true,
                installSource = AppInstallSource.STORE
            )
        )
        assertEquals(AppRiskLevel.HIGH, result.level)
        assertTrue(result.score >= 45)
    }

    @Test
    fun sideloadedSmsContactsBootCombinationIsHighRiskIndicator() {
        val result = AppRiskEvaluator.evaluate(
            AppRiskInput(
                requestedPermissions = setOf(
                    "android.permission.READ_SMS",
                    "android.permission.READ_CONTACTS",
                    "android.permission.RECEIVE_BOOT_COMPLETED"
                ),
                hasAccessibilityService = false,
                installSource = AppInstallSource.LOCAL_FILE
            )
        )
        assertEquals(AppRiskLevel.HIGH, result.level)
        assertTrue(result.score >= 45)
    }

    @Test
    fun knownThreatAlwaysWinsOverHeuristics() {
        val result = AppRiskEvaluator.evaluate(
            AppRiskInput(
                requestedPermissions = emptySet(),
                hasAccessibilityService = false,
                installSource = AppInstallSource.STORE,
                knownThreatReference = "1042"
            )
        )
        assertEquals(100, result.score)
        assertEquals(AppRiskLevel.KNOWN_THREAT, result.level)
    }
}
