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
    val phishingHosts: Int = 0,
    val c2Hosts: Int = 0,
    val latestAndroidSecurityPatch: String? = null,
    val androidCveCount: Int = 0,
    val successfulSourcesLastRun: Int = 0,
    val failedSourcesLastRun: Int = 0,
    val freshSources: Int = 0,
    val staleSources: Int = 0,
    val totalSources: Int = AutonomousFeedPolicy.all.size,
    val sourceHealth: List<AutonomousSourceHealth> = emptyList()
)

sealed class AutonomousUpdateResult {
    data class Success(val info: AutonomousIntelInfo, val changedSources: Int) : AutonomousUpdateResult()
    data class Partial(val info: AutonomousIntelInfo, val successfulSources: Int, val failedSources: Int, val changedSources: Int) : AutonomousUpdateResult()
    data object NoSourceAvailable : AutonomousUpdateResult()
}
