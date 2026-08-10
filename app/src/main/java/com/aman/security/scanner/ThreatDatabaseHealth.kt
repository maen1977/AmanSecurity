package com.aman.security.scanner

import java.time.Duration
import java.time.Instant

enum class ThreatDatabaseFreshness {
    CURRENT,
    AGING,
    STALE,
    UNKNOWN
}

object ThreatDatabaseHealth {
    private const val CURRENT_DAYS = 2L
    private const val AGING_DAYS = 7L
    private const val MAX_FUTURE_SKEW_HOURS = 24L

    fun classify(generatedAt: String, now: Instant = Instant.now()): ThreatDatabaseFreshness {
        val generated = runCatching { Instant.parse(generatedAt) }.getOrNull()
            ?: return ThreatDatabaseFreshness.UNKNOWN
        if (generated.isAfter(now.plus(Duration.ofHours(MAX_FUTURE_SKEW_HOURS)))) {
            return ThreatDatabaseFreshness.UNKNOWN
        }
        val ageDays = Duration.between(generated, now).toDays().coerceAtLeast(0)
        return when {
            ageDays <= CURRENT_DAYS -> ThreatDatabaseFreshness.CURRENT
            ageDays <= AGING_DAYS -> ThreatDatabaseFreshness.AGING
            else -> ThreatDatabaseFreshness.STALE
        }
    }
}
