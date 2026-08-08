package com.aman.security.scanner

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Test

class ThreatDatabaseHealthTest {
    private val now = Instant.parse("2026-08-08T12:00:00Z")

    @Test
    fun freshDatabaseIsCurrent() {
        assertEquals(
            ThreatDatabaseFreshness.CURRENT,
            ThreatDatabaseHealth.classify("2026-08-06T12:00:00Z", now)
        )
    }

    @Test
    fun monthOldDatabaseIsAgingButNotCurrent() {
        assertEquals(
            ThreatDatabaseFreshness.AGING,
            ThreatDatabaseHealth.classify("2026-07-15T12:00:00Z", now)
        )
    }

    @Test
    fun olderDatabaseIsStale() {
        assertEquals(
            ThreatDatabaseFreshness.STALE,
            ThreatDatabaseHealth.classify("2026-06-01T12:00:00Z", now)
        )
    }

    @Test
    fun invalidOrFarFutureTimestampIsUnknown() {
        assertEquals(ThreatDatabaseFreshness.UNKNOWN, ThreatDatabaseHealth.classify("bad", now))
        assertEquals(
            ThreatDatabaseFreshness.UNKNOWN,
            ThreatDatabaseHealth.classify("2026-08-10T12:00:00Z", now)
        )
    }
}
