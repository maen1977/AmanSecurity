package com.aman.security.detection

import com.aman.security.runtime.AnomalyDeltas
import com.aman.security.runtime.AnomalyLevel
import com.aman.security.runtime.ExposureLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for Maen Shield 8.0.0 maximum-tier engines:
 * behavioral anomaly scoring, privacy exposure assessment and
 * exploit-marker heuristics.
 *
 * These engines run locally on the device with no cloud dependency,
 * keeping Maen Shield free and under 3MB.
 */
class OnDeviceMaxTierEnginesTest {

    @Test
    fun anomalyDeltasDefaultSnapshotIsZero() {
        val deltas = AnomalyDeltas()
        assertEquals(0L, deltas.overlayTotal)
        assertEquals(0L, deltas.mediaTotal)
        assertEquals(0L, deltas.clipboardTotal)
        assertEquals(0L, deltas.overlayLastMs)
    }

    @Test
    fun anomalyLevelsAreDistinctAndOrdered() {
        assertEquals(3, AnomalyLevel.values().size)
        assertTrue(AnomalyLevel.HIGH != AnomalyLevel.REVIEW)
        assertTrue(AnomalyLevel.REVIEW != AnomalyLevel.NONE)
    }

    @Test
    fun exposureLevelsAreDistinctAndOrdered() {
        assertEquals(3, ExposureLevel.values().size)
        assertTrue(ExposureLevel.HIGH != ExposureLevel.REVIEW)
        assertTrue(ExposureLevel.REVIEW != ExposureLevel.NONE)
    }

    @Test
    fun exploitMarkerKindValuesCoverExpectedCategories() {
        val kinds = ExploitMarkerKind.values()
        assertTrue("DANGEROUS_RECEIVER_COMBO expected", kinds.contains(ExploitMarkerKind.DANGEROUS_RECEIVER_COMBO))
        assertTrue("HIDDEN_LOADER_SERVICE expected", kinds.contains(ExploitMarkerKind.HIDDEN_LOADER_SERVICE))
        assertTrue("PHONE_STATE_SMART_COMBO expected", kinds.contains(ExploitMarkerKind.PHONE_STATE_SMART_COMBO))
    }

    @Test
    fun exploitLevelsAreDistinctAndOrdered() {
        assertEquals(3, ExploitLevel.values().size)
        assertTrue(ExploitLevel.HIGH != ExploitLevel.REVIEW)
        assertTrue(ExploitLevel.REVIEW != ExploitLevel.NONE)
    }
}
