package com.aman.security.security

/**
 * Keeps protection readiness honest: a successful self-test is evidence for a
 * bounded period, not a permanent guarantee. This is deterministic and has no
 * network, worker, or battery cost.
 */
object ProtectionVerificationFreshness {
    const val DEFAULT_MAX_AGE_MS: Long = 7L * 24L * 60L * 60L * 1000L

    fun isFresh(
        passed: Boolean,
        testedAt: Long,
        now: Long,
        maxAgeMs: Long = DEFAULT_MAX_AGE_MS
    ): Boolean {
        if (!passed || testedAt <= 0L || maxAgeMs < 0L || now < testedAt) return false
        return now - testedAt <= maxAgeMs
    }
}
