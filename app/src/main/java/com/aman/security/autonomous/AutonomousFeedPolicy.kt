package com.aman.security.autonomous

import java.util.concurrent.TimeUnit

enum class AutonomousFeedTrust {
    PRIMARY,
    COMMUNITY,
    VULNERABILITY
}

data class AutonomousFeedDescriptor(
    val key: String,
    val trust: AutonomousFeedTrust,
    val lookupTtlMs: Long,
    val statusFreshMs: Long,
    val minEntries: Int,
    val maxEntries: Int,
    val canConfirmThreat: Boolean
)

/**
 * Phone-side policy after 3.5: the handset consumes one compact Aman package only.
 * Upstream feeds are aggregated and normalized in GitHub Actions, never parsed on-device.
 */
object AutonomousFeedPolicy {
    val cloudBundle = AutonomousFeedDescriptor(
        key = AutonomousThreatStore.SOURCE_CLOUD_BUNDLE,
        trust = AutonomousFeedTrust.PRIMARY,
        lookupTtlMs = TimeUnit.DAYS.toMillis(7),
        statusFreshMs = TimeUnit.HOURS.toMillis(30),
        minEntries = 1,
        maxEntries = 550_000,
        canConfirmThreat = true
    )

    val all = listOf(cloudBundle)

    val phishingPrimaryTtlMs: Long = TimeUnit.DAYS.toMillis(7)
    val phishingOpenPhishTtlMs: Long = TimeUnit.HOURS.toMillis(48)
    val phishingCommunityTtlMs: Long = TimeUnit.DAYS.toMillis(7)
    val malwareUrlsTtlMs: Long = TimeUnit.HOURS.toMillis(48)
    val c2TtlMs: Long = TimeUnit.HOURS.toMillis(48)
}
