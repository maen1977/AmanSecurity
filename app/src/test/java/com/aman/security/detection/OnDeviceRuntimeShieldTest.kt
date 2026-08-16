package com.aman.security.detection

import com.aman.security.runtime.ClipboardGuard
import com.aman.security.runtime.ForegroundKind
import com.aman.security.runtime.OverlayWatchdog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for the on-device Runtime Shield engines added in 7.0.0.
 *
 * These engines run locally on the device with no cloud dependency,
 * keeping Maen Shield free and under 3MB.
 */
class OnDeviceRuntimeShieldTest {

    @Test
    fun clipboardGuardSecretPatternsCoverOtpCodes() {
        val otpSamples = listOf(
            "كود التحقق الخاص بك هو 482716",
            "Your verification code is 918273",
            "رمزك: 159248. لا تشاركه مع أحد",
            "code: 847291"
        )
        val patterns = ClipboardGuard.SECRET_PATTERNS
        assertTrue("At least one OTP sample must match a secret pattern", otpSamples.any { text ->
            patterns.any { regex -> regex.containsMatchIn(text) }
        })
        // The 6-digit code pattern is the primary OTP catcher.
        assertTrue("Six-digit code pattern expected", patterns.any { it.matches("482716") || it.containsMatchIn("482716") })
    }

    @Test
    fun clipboardGuardSecretPatternsCoverCardAndIban() {
        val patterns = ClipboardGuard.SECRET_PATTERNS
        val card = "4111111111111111"
        val spaced = "5500-0000-0000-0004"
        val iban = "IBAN SA4420000001234567891234"
        assertTrue("Card number pattern expected", patterns.any { it.containsMatchIn(card) })
        assertTrue("Spaced card pattern expected", patterns.any { it.containsMatchIn(spaced) })
        assertTrue("IBAN pattern expected", patterns.any { it.containsMatchIn(iban) })
    }

    @Test
    fun clipboardGuardNormalTextDoesNotMatchSecretPatterns() {
        val normalSamples = listOf(
            "مرحباً كيف حالك",
            "Hello world, how are you?",
            "سأكون جاهزاً الساعة الخامسة",
            "The meeting is at noon tomorrow"
        )
        val patterns = ClipboardGuard.SECRET_PATTERNS
        for (sample in normalSamples) {
            val matched = patterns.any { it.containsMatchIn(sample) }
            assertTrue("Normal text should not match a secret pattern: $sample", !matched)
        }
    }

    @Test
    fun overlayWatchdogOverlayRelevantPermissionsAreBroad() {
        val perms = OverlayWatchdog.OVERLAY_RELEVANT_PERMISSIONS
        assertTrue("Overlay guard must watch the draw-over-other-apps permission", "android.permission.SYSTEM_ALERT_WINDOW" in perms)
        assertTrue("Overlay guard must watch the camera", "android.permission.CAMERA" in perms)
        assertTrue("Overlay guard must watch the microphone", "android.permission.RECORD_AUDIO" in perms)
        assertTrue("Overlay guard must watch SMS access", "android.permission.READ_SMS" in perms)
    }

    @Test
    fun overlayWatchdogSensitivePackagePrefixesKnown() {
        val prefixes = OverlayWatchdog.KNOWN_SENSITIVE_PREFIXES
        assertNotNull(prefixes)
        assertTrue("Google Pay package prefix expected", "com.google.android.apps.nbu.paisa" in prefixes)
        assertTrue("PayPal package prefix expected", "com.paypal.android" in prefixes)
    }

    @Test
    fun foregroundKindCountsAreComplete() {
        val kinds = ForegroundKind.values()
        assertTrue("OVERLAY_ATTACK missing", kinds.contains(ForegroundKind.OVERLAY_ATTACK))
        assertTrue("MEDIA_ACCESS missing", kinds.contains(ForegroundKind.MEDIA_ACCESS))
        assertTrue("CLIPBOARD_GUARD missing", kinds.contains(ForegroundKind.CLIPBOARD_GUARD))
        assertTrue("HARDENING_WEAK missing", kinds.contains(ForegroundKind.HARDENING_WEAK))
        assertTrue("ENTERED_SESSION missing", kinds.contains(ForegroundKind.ENTERED_SESSION))
        assertEquals("Exactly five foreground kinds expected", 5, kinds.size)
    }
}
