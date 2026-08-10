package com.aman.security.protection

import com.aman.security.scanner.AppInstallSource
import com.aman.security.scanner.AppRiskLevel
import com.aman.security.scanner.InstalledAppScanResult
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRescanPolicyTest {
    private fun app(
        level: AppRiskLevel,
        hash: String = "a".repeat(64),
        version: String = "1.0",
        reference: String? = null
    ) = InstalledAppScanResult(
        appName = "Sample",
        packageName = "com.example.sample",
        versionName = version,
        installSource = AppInstallSource.STORE,
        riskScore = if (level == AppRiskLevel.KNOWN_THREAT) 100 else if (level == AppRiskLevel.HIGH) 60 else 10,
        riskLevel = level,
        signals = emptySet(),
        apkSha256 = hash,
        signingCertificateSha256 = "b".repeat(64),
        threatReference = reference
    )

    @Test fun lowRiskNeverNotifies() {
        assertFalse(AppRescanPolicy.shouldNotify(null, app(AppRiskLevel.LOW)))
    }

    @Test fun firstHighRiskFindingNotifies() {
        assertTrue(AppRescanPolicy.shouldNotify(null, app(AppRiskLevel.HIGH)))
    }

    @Test fun unchangedHighRiskFindingIsSuppressed() {
        val current = app(AppRiskLevel.HIGH)
        assertFalse(AppRescanPolicy.shouldNotify(AppRescanPolicy.fingerprint(current), current))
    }

    @Test fun changedApkHashCanNotifyAgain() {
        val old = app(AppRiskLevel.HIGH, hash = "a".repeat(64))
        val updated = app(AppRiskLevel.HIGH, hash = "c".repeat(64))
        assertTrue(AppRescanPolicy.shouldNotify(AppRescanPolicy.fingerprint(old), updated))
    }

    @Test fun newConfirmedThreatReferenceCanNotifyAgain() {
        val old = app(AppRiskLevel.HIGH)
        val known = app(AppRiskLevel.KNOWN_THREAT, reference = "MB-NEW-THREAT")
        assertTrue(AppRescanPolicy.shouldNotify(AppRescanPolicy.fingerprint(old), known))
    }
}
