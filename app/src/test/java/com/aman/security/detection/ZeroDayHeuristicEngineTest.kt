package com.aman.security.detection

import com.aman.security.scanner.ApkRiskSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ZeroDayHeuristicEngineTest {
    @Test
    fun hiddenDexWithDynamicLoaderProducesDropperFinding() {
        val findings = ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = setOf(ApkRiskSignal.DYNAMIC_CODE_LOADING),
                markers = setOf("DYNAMIC_CODE", "HIDDEN_DEX_PAYLOAD"),
                hiddenDexPayloadCount = 1
            )
        )
        assertTrue(findings.any { it.id == "ZERO_DAY_HIDDEN_DEX_LOADER" && it.family == ThreatFamily.DROPPER })
        assertTrue(findings.any { it.confidence == FindingConfidence.HIGH })
    }

    @Test
    fun entropyAloneDoesNotCreateMaliciousFinding() {
        val findings = ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = emptySet(),
                markers = setOf("HIGH_ENTROPY_ASSET"),
                highEntropyAssetCount = 4
            )
        )
        assertEquals(0, findings.size)
    }

    @Test
    fun antiAnalysisAloneNeedsCorroboratingCapabilities() {
        val findings = ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = emptySet(),
                markers = setOf("ANTI_DEBUG", "EMULATOR_CHECK")
            )
        )
        assertEquals(0, findings.size)
    }

    @Test
    fun stealthAntiAnalysisNetworkChainIsHighConfidence() {
        val findings = ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = emptySet(),
                markers = setOf("ANTI_DEBUG", "EMULATOR_CHECK", "HIDE_COMPONENT", "NETWORK_CLIENT")
            )
        )
        assertTrue(findings.any { it.id == "ZERO_DAY_STEALTH_ANTI_ANALYSIS" && it.confidence == FindingConfidence.HIGH })
    }

    @Test
    fun stealthNativePayloadChainIsHighConfidence() {
        val findings = ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = emptySet(),
                markers = setOf("HIDE_COMPONENT", "PACKER_PRESENT"),
                hiddenElfPayloadCount = 1
            )
        )
        assertTrue(findings.any { it.id == "ZERO_DAY_STEALTH_NATIVE_PAYLOAD" && it.confidence == FindingConfidence.HIGH })
    }

    @Test
    fun overlayBankerChainRequiresAccessibilityAndOverlayPermission() {
        val findings = ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = setOf(ApkRiskSignal.OVERLAY_PERMISSION, ApkRiskSignal.SMS_API),
                markers = setOf("ACCESSIBILITY_NODE", "NETWORK_CLIENT")
            )
        )
        assertTrue(findings.any { it.id == "ZERO_DAY_OVERLAY_BANKER_CHAIN" && it.family == ThreatFamily.BANKER })
    }

    @Test
    fun screenCaptureExfilChainIsHighConfidence() {
        val findings = ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = emptySet(),
                markers = setOf("SCREEN_CAPTURE", "COMMAND_EXEC", "NETWORK_CLIENT")
            )
        )
        assertTrue(findings.any { it.id == "ZERO_DAY_SCREEN_EXFIL_CHAIN" && it.confidence == FindingConfidence.HIGH })
    }

    @Test
    fun notificationListenerWithDeviceIdIsMediumExfilFinding() {
        val findings = ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = setOf(ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE),
                markers = setOf("DEVICE_ID", "NETWORK_CLIENT")
            )
        )
        assertTrue(findings.any { it.id == "ZERO_DAY_NOTIFICATION_EXFIL" && it.confidence == FindingConfidence.MEDIUM })
    }

    @Test
    fun partialZeroDayChainDoesNotTriggerFalseFinding() {
        val findings = ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = emptySet(),
                markers = setOf("ACCESSIBILITY_NODE", "NETWORK_CLIENT"),
                hiddenElfPayloadCount = 1
            )
        )
        assertEquals(false, findings.any { it.id == "ZERO_DAY_STEALTH_NATIVE_PAYLOAD" })
    }
