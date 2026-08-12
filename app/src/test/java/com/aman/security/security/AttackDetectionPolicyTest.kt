package com.aman.security.security

import org.junit.Assert.assertEquals
import org.junit.Test

class AttackDetectionPolicyTest {
    @Test
    fun healthyAndQuietIsClear() {
        assertEquals(
            AttackDetectionLevel.CLEAR,
            AttackDetectionPolicy.level(AttackDetectionInput(true, true, 0, 0))
        )
    }

    @Test
    fun blockedOrReviewSignalIsWatchNotCompromise() {
        assertEquals(
            AttackDetectionLevel.WATCH,
            AttackDetectionPolicy.level(AttackDetectionInput(true, true, 0, 2))
        )
    }

    @Test
    fun corroboratedCriticalSignalWins() {
        assertEquals(
            AttackDetectionLevel.CRITICAL,
            AttackDetectionPolicy.level(AttackDetectionInput(true, true, 1, 4))
        )
    }

    @Test
    fun stoppedProtectionIsIncompleteEvenWithoutSignals() {
        assertEquals(
            AttackDetectionLevel.INCOMPLETE,
            AttackDetectionPolicy.level(AttackDetectionInput(true, false, 0, 0))
        )
    }
}
