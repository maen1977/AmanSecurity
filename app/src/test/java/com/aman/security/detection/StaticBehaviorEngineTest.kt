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
}
