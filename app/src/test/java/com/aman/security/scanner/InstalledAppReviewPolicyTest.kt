package com.aman.security.scanner

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstalledAppReviewPolicyTest {
    @Test
    fun ordinaryStoreAppWithCapabilityOnlyMediumIsNotSurfaced() {
        val result = result(
            installSource = AppInstallSource.STORE,
            riskLevel = AppRiskLevel.MEDIUM
        )

        assertFalse(InstalledAppReviewPolicy.shouldSurfaceInFullScan(result))
    }

    @Test
    fun unknownInstallerCapabilityOnlyMediumIsNotSurfaced() {
        val result = result(
            installSource = AppInstallSource.UNKNOWN,
            riskLevel = AppRiskLevel.MEDIUM
        )

        assertFalse(InstalledAppReviewPolicy.shouldSurfaceInFullScan(result))
    }

    @Test
    fun sideloadedMediumAppRemainsReviewable() {
        val result = result(
            installSource = AppInstallSource.LOCAL_FILE,
            riskLevel = AppRiskLevel.MEDIUM
        )

        assertTrue(InstalledAppReviewPolicy.shouldSurfaceInFullScan(result))
    }

    @Test
    fun confirmedThreatAlwaysRemainsVisible() {
        val result = result(
            installSource = AppInstallSource.STORE,
            riskLevel = AppRiskLevel.KNOWN_THREAT
        )

        assertTrue(InstalledAppReviewPolicy.shouldSurfaceInFullScan(result))
    }

    private fun result(
        installSource: AppInstallSource,
        riskLevel: AppRiskLevel
    ) = InstalledAppScanResult(
        appName = "Test app",
        packageName = "com.example.test",
        versionName = "1.0",
        installSource = installSource,
        riskScore = if (riskLevel == AppRiskLevel.KNOWN_THREAT) 100 else 55,
        riskLevel = riskLevel,
        signals = emptySet(),
        apkSha256 = null,
        signingCertificateSha256 = null
    )
}
