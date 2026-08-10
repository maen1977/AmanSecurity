package com.aman.security.scanner

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Test

class ThreatDatabaseHealthTest {
    private val now = Instant.parse("2026-08-08T12:00:00Z")

    @Test
    fun databaseUpToTwoDaysOldIsCurrent() {
        assertEquals(
            ThreatDatabaseFreshness.CURRENT,
            ThreatDatabaseHealth.classify("2026-08-06T12:00:00Z", now)
        )
    }

    @Test
    fun databaseThreeToSevenDaysOldIsAging() {
        assertEquals(
            ThreatDatabaseFreshness.AGING,
            ThreatDatabaseHealth.classify("2026-08-03T12:00:00Z", now)
        )
    }

    @Test
    fun databaseOlderThanSevenDaysIsStale() {
        assertEquals(
            ThreatDatabaseFreshness.STALE,
            ThreatDatabaseHealth.classify("2026-07-31T12:00:00Z", now)
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
