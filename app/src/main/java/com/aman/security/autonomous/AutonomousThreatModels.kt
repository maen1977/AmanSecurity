package com.aman.security.autonomous

data class AutonomousSourceHealth(
    val key: String,
    val trust: AutonomousFeedTrust,
    val lastSuccessEpochMs: Long,
    val ageHours: Long?,
    val fresh: Boolean,
    val itemCount: Int,
    val consecutiveFailures: Int
)

data class AutonomousIntelInfo(
    val lastSuccessfulUpdateEpochMs: Long = 0L,
    val lastAttemptEpochMs: Long = 0L,
    val malwareFileHashes: Int = 0,
    val phishingPrimaryHosts: Int = 0,
    val phishingOpenPhishHosts: Int = 0,
    val phishingCommunityHosts: Int = 0,
    val phishingHosts: Int = 0,
    val malwareUrlHosts: Int = 0,
    val c2Hosts: Int = 0,
    val latestAndroidSecurityPatch: String? = null,
    val androidCveCount: Int = 0,
    val apkIdentityEntries: Int = 0,
    val detectionRuleEntries: Int = 0,
    val successfulSourcesLastRun: Int = 0,
    val failedSourcesLastRun: Int = 0,
    val upstreamSourceCount: Int = 0,
    val upstreamSourceFailures: Int = 0,
    val upstreamSourceSkipped: Int = 0,
    val freshSources: Int = 0,
    val staleSources: Int = 0,
    val totalSources: Int = AutonomousFeedPolicy.all.size,
    val sourceHealth: List<AutonomousSourceHealth> = emptyList(),
    val cloudSerial: Long = 0L,
    val cloudVersion: String? = null,
    val cloudGeneratedAt: String? = null,
    val cloudGeneratedAtEpochMs: Long = 0L,
    val cloudPackageFresh: Boolean = false,
    val cloudConsecutiveFailures: Int = 0
)


enum class AutonomousUpdatePhase { CONNECTING, DOWNLOADING, PARSING, INDEXING, APPLYING }

/** Fine-grained, lightweight progress for one threat-intelligence source. */
data class AutonomousUpdateProgress(
    val sourceKey: String,
    val sourceIndex: Int,
    val totalSources: Int,
    val completedSources: Int,
    val phase: AutonomousUpdatePhase = AutonomousUpdatePhase.CONNECTING,
    val phaseProgress: Int = 0,
    val downloadedBytes: Long = 0L,
    val totalBytes: Long = -1L,
    val sourceFinished: Boolean = false,
    val sourceSucceeded: Boolean? = null
)

sealed class AutonomousUpdateResult {
    data class Success(val info: AutonomousIntelInfo, val changedSources: Int) : AutonomousUpdateResult()
    data class Partial(val info: AutonomousIntelInfo, val successfulSources: Int, val failedSources: Int, val changedSources: Int) : AutonomousUpdateResult()
    data class NoSourceAvailable(val error: String = "no_source_available") : AutonomousUpdateResult()
}
