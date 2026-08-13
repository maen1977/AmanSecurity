package com.aman.security.autonomous

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

class AutonomousFeedPolicyTest {
    @Test fun phoneConsumesOneTrustedCloudBundle() {
        assertEquals(1, AutonomousFeedPolicy.all.size)
        assertEquals(AutonomousThreatStore.SOURCE_CLOUD_BUNDLE, AutonomousFeedPolicy.cloudBundle.key)
        assertTrue(AutonomousFeedPolicy.cloudBundle.canConfirmThreat)
        assertEquals(AutonomousFeedTrust.PRIMARY, AutonomousFeedPolicy.cloudBundle.trust)
    }

    @Test fun transientCloudIndicatorsHaveBoundedFreshness() {
        assertTrue(AutonomousFeedPolicy.phishingOpenPhishTtlMs <= TimeUnit.DAYS.toMillis(2))
        assertTrue(AutonomousFeedPolicy.malwareUrlsTtlMs <= TimeUnit.DAYS.toMillis(2))
        assertTrue(AutonomousFeedPolicy.c2TtlMs <= TimeUnit.DAYS.toMillis(2))
        assertTrue(AutonomousFeedPolicy.phishingPrimaryTtlMs <= TimeUnit.DAYS.toMillis(7))
    }
}
