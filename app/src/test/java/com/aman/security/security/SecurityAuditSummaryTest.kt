package com.aman.security.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityAuditSummaryTest {
    @Test
    fun `high and warning findings reduce posture conservatively`() {
        val summary = SecurityAuditSummary(
            device = DeviceSecurityAudit(
                screenLockSecure = false,
                developerOptionsEnabled = true,
                adbEnabled = false,
                automaticTimeEnabled = true,
                automaticTimeZoneEnabled = true,
                rootSignals = 0,
                securityPatch = "2026-08-01",
                findings = listOf(
                    SecurityAuditFinding("lock", SecurityAuditSeverity.HIGH),
                    SecurityAuditFinding("dev", SecurityAuditSeverity.WARNING)
                )
            ),
            network = NetworkSecurityAudit(
                connected = true,
                validated = true,
                captivePortal = false,
                vpnActive = false,
                privateDnsActive = true,
                metered = false,
                transport = NetworkTransportType.WIFI,
                findings = emptyList()
            ),
            privacy = PrivacyPermissionAudit(10, 4, 2, 11, emptyList())
        )
        assertEquals(1, summary.highFindings)
        assertEquals(1, summary.warningFindings)
        assertEquals(18, summary.posturePenalty)
    }

    @Test
    fun `privacy review keeps app identity and granted permissions`() {
        val reviewApp = PrivacyAppExposure(
            appName = "Example Messenger",
            packageName = "com.example.messenger",
            grantedSensitivePermissions = 6,
            grantedPermissions = listOf(
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CALL_LOG",
                "android.permission.READ_SMS"
            )
        )
        val audit = PrivacyPermissionAudit(
            scannedApps = 10,
            appsWithSensitivePermissions = 3,
            elevatedPermissionApps = 1,
            totalGrantedSensitivePermissions = 6,
            findings = listOf(SecurityAuditFinding("privacy_permission_review", SecurityAuditSeverity.WARNING)),
            reviewApps = listOf(reviewApp)
        )

        assertEquals("Example Messenger", audit.reviewApps.single().appName)
        assertEquals("com.example.messenger", audit.reviewApps.single().packageName)
        assertEquals(6, audit.reviewApps.single().grantedSensitivePermissions)
        assertTrue(audit.reviewApps.single().grantedPermissions.contains("android.permission.CAMERA"))
    }

    @Test
    fun `official store apps with common sensitive permissions are not privacy reviews`() {
        val officialPackages = listOf(
            "com.whatsapp",
            "com.facebook.orca",
            "org.telegram.messenger",
            "com.truecaller",
            "com.google.android.apps.docs",
            "com.google.android.apps.adm",
            "com.miui.screenrecorder"
        )

        officialPackages.forEach { packageName ->
            val app = PrivacyAppExposure(
                appName = packageName,
                packageName = packageName,
                grantedSensitivePermissions = 6,
                isTrustedInstall = true
            )
            assertFalse("$packageName should not be a capability-only review", PrivacyPermissionReviewPolicy.shouldReview(app))
        }
    }

    @Test
    fun `sideloaded high-permission app remains a privacy review`() {
        val sideloadedWhatsApp = PrivacyAppExposure(
            appName = "WhatsApp",
            packageName = "com.whatsapp",
            grantedSensitivePermissions = 6,
            isTrustedInstall = false
        )

        assertTrue(PrivacyPermissionReviewPolicy.shouldReview(sideloadedWhatsApp))
    }

    @Test
    fun `only recognized app stores are trusted installers`() {
        listOf(
            "com.android.vending",
            "com.samsung.android.app.galaxyapps",
            "com.amazon.venezia",
            "com.huawei.appmarket",
            "com.oppo.market",
            "com.vivo.appstore",
            "com.xiaomi.mipicks",
            "com.heytap.market",
            "com.transsion.market"
        ).forEach { installer ->
            assertTrue(installer, PrivacyPermissionReviewPolicy.isTrustedInstaller(installer))
        }
        assertFalse(PrivacyPermissionReviewPolicy.isTrustedInstaller(null))
        assertFalse(PrivacyPermissionReviewPolicy.isTrustedInstaller("com.android.shell"))
        assertFalse(PrivacyPermissionReviewPolicy.isTrustedInstaller(""))
    }

    @Test
    fun `penalty is bounded`() {
        val high = List(10) { SecurityAuditFinding("h$it", SecurityAuditSeverity.HIGH) }
        val summary = SecurityAuditSummary(
            DeviceSecurityAudit(true, false, false, true, true, 0, "", high),
            NetworkSecurityAudit(false, false, false, false, false, false, NetworkTransportType.NONE, high),
            PrivacyPermissionAudit(100, 100, 100, 500, high)
        )
        assertTrue(summary.posturePenalty <= 35)
    }
}
