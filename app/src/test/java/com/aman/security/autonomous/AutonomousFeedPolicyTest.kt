package com.aman.security.autonomous

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutonomousFeedPolicyTest {
    @Test fun communityFeedCannotIndependentlyConfirmThreat() {
        assertFalse(AutonomousFeedPolicy.phishingCommunity.canConfirmThreat)
        assertTrue(AutonomousFeedPolicy.phishingPrimary.canConfirmThreat)
        assertTrue(AutonomousFeedPolicy.c2.canConfirmThreat)
    }

    @Test fun immutableFileHashesRemainLookupPersistent() {
        assertTrue(AutonomousFeedPolicy.malware.lookupTtlMs == Long.MAX_VALUE)
    }

    @Test fun transientInfrastructureHasBoundedTtl() {
        assertTrue(AutonomousFeedPolicy.c2.lookupTtlMs < AutonomousFeedPolicy.phishingPrimary.lookupTtlMs)
    }

    @Test(expected = IllegalArgumentException::class)
    fun oversizedCommunitySnapshotIsRejected() {
        AutonomousFeedPolicy.validateCount(
            AutonomousThreatStore.SOURCE_PHISH_COMMUNITY,
            AutonomousFeedPolicy.phishingCommunity.maxEntries + 1
        )
    }
}
