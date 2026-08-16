package com.aman.security.detection

import com.aman.security.scanner.ApkRiskSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class StaticBehaviorEngineTest {
    @Test
    fun accessibilityAndOverlayProducesBankerSignal() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.ACCESSIBILITY_SERVICE, ApkRiskSignal.OVERLAY_PERMISSION),
            markers = emptySet()
        )
        assertTrue(findings.any { it.family == ThreatFamily.BANKER })
    }

    @Test
    fun singleGenericMarkerDoesNotTriggerBehaviorCombination() {
        val findings = StaticBehaviorEngine.evaluate(emptySet(), setOf("NETWORK_CLIENT"))
        assertEquals(0, findings.size)
    }

    @Test
    fun mediaSurveillanceTripletProducesStalkerwareFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.CAMERA, ApkRiskSignal.MICROPHONE, ApkRiskSignal.PRECISE_LOCATION),
            markers = emptySet()
        )
        assertEquals(ThreatFamily.STALKERWARE, findings.first().family)
        assertEquals("BEHAVIOR_MEDIA_SURVEILLANCE", findings.first().id)
    }

    @Test
    fun smsAccessWithDeviceIdentifierProducesOtpTheftFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.SMS_ACCESS, ApkRiskSignal.DEVICE_IDENTIFIER_API),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_OTP_THEFT" && it.family == ThreatFamily.BANKER })
    }

    @Test
    fun vpnWithAccessibilityProducesBankerFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.VPN_SERVICE, ApkRiskSignal.ACCESSIBILITY_SERVICE),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_VPN_ACCESSIBILITY" })
    }

    @Test
    fun adminWithInstallAndNetworkProducesPersistenceFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(
                ApkRiskSignal.DEVICE_ADMIN_RECEIVER,
                ApkRiskSignal.REQUEST_INSTALL_PACKAGES
            ),
            markers = setOf("NETWORK_CLIENT")
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_ADMIN_INSTALL_PERSISTENCE" && it.confidence == FindingConfidence.HIGH })
    }

    @Test
    fun smsApiWithCallLogAndBootProducesExfilFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(
                ApkRiskSignal.SMS_API,
                ApkRiskSignal.CALL_LOG_ACCESS,
                ApkRiskSignal.BOOT_START
            ),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_SMS_EXFIL_PERSISTENCE" })
    }

    @Test
    fun overlayWithInstallPackagesProducesBankerFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.OVERLAY_PERMISSION, ApkRiskSignal.REQUEST_INSTALL_PACKAGES),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_OVERLAY_INSTALLER" })
    }

    @Test
    fun telephonyStateWithSmsAccessProducesSimOtpInterceptionFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.TELEPHONY_STATE_API, ApkRiskSignal.SMS_ACCESS),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_SIM_OTP_INTERCEPTION" && it.family == ThreatFamily.BANKER })
    }

    @Test
    fun billingApiWithAccessibilityProducesOverlayFraudFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.BILLING_API, ApkRiskSignal.ACCESSIBILITY_SERVICE),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_BILLING_OVERLAY_FRAUD" && it.family == ThreatFamily.BANKER })
    }

    @Test
    fun billingApiWithMicrophoneProducesMediaProfileFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.BILLING_API, ApkRiskSignal.MICROPHONE),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_BILLING_MEDIA_PROFILE" })
    }

    @Test
    fun manageStorageWithSmsAccessProducesStorageSweepFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.MANAGE_EXTERNAL_STORAGE_API, ApkRiskSignal.SMS_ACCESS),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_STORAGE_SWEEP" && it.family == ThreatFamily.SPYWARE })
    }

    @Test
    fun readPhoneStateWithContactsProducesIdentityExfilFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.READ_PHONE_STATE_API, ApkRiskSignal.CONTACTS_ACCESS),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_IDENTITY_EXFIL" })
    }

    @Test
    fun partialChainDoesNotTriggerFalseBehaviorFinding() {
        // Only camera and microphone without location should not trigger media surveillance.
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.CAMERA, ApkRiskSignal.MICROPHONE),
            markers = emptySet()
        )
        assertEquals(false, findings.any { it.id == "BEHAVIOR_MEDIA_SURVEILLANCE" })
        // Only overlay without install packages should not trigger overlay installer.
        assertEquals(false, findings.any { it.id == "BEHAVIOR_OVERLAY_INSTALLER" })
    }

    @Test
    fun audioRecordingServiceWithContactsProducesCovertListeningFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.AUDIO_RECORDING_SERVICE, ApkRiskSignal.CONTACTS_ACCESS),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_COVERT_LISTENING_PROFILE" })
    }

    @Test
    fun storageControlWithCameraProducesMediaHarvestingFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.MANAGE_EXTERNAL_STORAGE_API, ApkRiskSignal.CAMERA),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_MEDIA_HARVESTING" && it.family == ThreatFamily.SPYWARE })
    }

    @Test
    fun notificationListenerWithTelephonyStateProducesTelemetryFinding() {
        val findings = StaticBehaviorEngine.evaluate(
            signals = setOf(ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE, ApkRiskSignal.TELEPHONY_STATE_API),
            markers = emptySet()
        )
        assertTrue(findings.any { it.id == "BEHAVIOR_NOTIFICATION_TELEPHONY_TELEMETRY" })
    }
}
