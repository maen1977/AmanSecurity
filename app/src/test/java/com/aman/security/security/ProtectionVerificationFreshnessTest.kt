package com.aman.security.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionVerificationFreshnessTest {
    @Test
    fun passedTestWithinWindowIsFresh() {
        assertTrue(
            ProtectionVerificationFreshness.isFresh(
                passed = true,
                testedAt = 1_000L,
                now = 1_000L + ProtectionVerificationFreshness.DEFAULT_MAX_AGE_MS
            )
        )
    }

    @Test
    fun passedTestAfterWindowIsStale() {
        assertFalse(
            ProtectionVerificationFreshness.isFresh(
                passed = true,
                testedAt = 1_000L,
                now = 1_001L + ProtectionVerificationFreshness.DEFAULT_MAX_AGE_MS
            )
        )
    }

    @Test
    fun unpassedOrFutureTestCannotBeFresh() {
        assertFalse(
            ProtectionVerificationFreshness.isFresh(
                passed = false,
                testedAt = 1_000L,
                now = 1_000L
            )
        )
        assertFalse(
            ProtectionVerificationFreshness.isFresh(
                passed = true,
                testedAt = 2_000L,
                now = 1_000L
            )
        )
    }
}
