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
    val statusFreshMs: Long = TimeUnit.HOURS.toMillis(18),
    val minEntries: Int,
    val maxEntries: Int,
    val canConfirmThreat: Boolean
)

/**
 * Declarative source policy used both by ingestion and lookup. Remote indicator data is
 * accepted only inside bounded source-specific limits. Community-only data can request
 * review but cannot independently create a confirmed malicious verdict.
 */
object AutonomousFeedPolicy {
    val malware = AutonomousFeedDescriptor(
        key = AutonomousThreatStore.SOURCE_MALWARE,
        trust = AutonomousFeedTrust.PRIMARY,
        lookupTtlMs = Long.MAX_VALUE,
        minEntries = 1,
        maxEntries = 100_000,
        canConfirmThreat = true
    )
    val phishingPrimary = AutonomousFeedDescriptor(
        key = AutonomousThreatStore.SOURCE_PHISH_PRIMARY,
        trust = AutonomousFeedTrust.PRIMARY,
        lookupTtlMs = TimeUnit.DAYS.toMillis(7),
        minEntries = 10,
        maxEntries = 250_000,
        canConfirmThreat = true
    )
    val phishingOpenPhish = AutonomousFeedDescriptor(
        key = AutonomousThreatStore.SOURCE_PHISH_OPENPHISH,
        trust = AutonomousFeedTrust.PRIMARY,
        lookupTtlMs = TimeUnit.HOURS.toMillis(36),
        statusFreshMs = TimeUnit.HOURS.toMillis(30),
        minEntries = 20,
        maxEntries = 150_000,
        canConfirmThreat = true
    )
    val phishingCommunity = AutonomousFeedDescriptor(
        key = AutonomousThreatStore.SOURCE_PHISH_COMMUNITY,
        trust = AutonomousFeedTrust.COMMUNITY,
        lookupTtlMs = TimeUnit.DAYS.toMillis(7),
        minEntries = 10,
        maxEntries = 250_000,
        canConfirmThreat = false
    )
    val malwareUrls = AutonomousFeedDescriptor(
        key = AutonomousThreatStore.SOURCE_MALWARE_URLS,
        trust = AutonomousFeedTrust.PRIMARY,
        lookupTtlMs = TimeUnit.HOURS.toMillis(36),
        minEntries = 100,
        maxEntries = 500_000,
        canConfirmThreat = true
    )
    val c2 = AutonomousFeedDescriptor(
        key = AutonomousThreatStore.SOURCE_C2,
        trust = AutonomousFeedTrust.PRIMARY,
        lookupTtlMs = TimeUnit.HOURS.toMillis(36),
        minEntries = 1,
        maxEntries = 50_000,
        canConfirmThreat = true
    )
    val androidBulletin = AutonomousFeedDescriptor(
        key = AutonomousThreatStore.SOURCE_ANDROID_BULLETIN,
        trust = AutonomousFeedTrust.VULNERABILITY,
        lookupTtlMs = TimeUnit.DAYS.toMillis(45),
        minEntries = 0,
        maxEntries = 20_000,
        canConfirmThreat = false
    )

    val all = listOf(malware, phishingPrimary, phishingOpenPhish, phishingCommunity, malwareUrls, c2, androidBulletin)
    private val byKey = all.associateBy { it.key }

    fun forKey(key: String): AutonomousFeedDescriptor = requireNotNull(byKey[key]) { "Unknown source key" }

    fun validateCount(key: String, count: Int) {
        val descriptor = forKey(key)
        require(count in descriptor.minEntries..descriptor.maxEntries) {
            "Source entry count outside policy"
        }
    }
}
