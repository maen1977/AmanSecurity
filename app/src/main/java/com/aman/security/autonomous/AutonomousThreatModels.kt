package com.aman.security.autonomous

data class AutonomousIntelInfo(
    val lastSuccessfulUpdateEpochMs: Long = 0L,
    val malwareFileHashes: Int = 0,
    val phishingHosts: Int = 0,
    val c2Hosts: Int = 0,
    val latestAndroidSecurityPatch: String? = null,
    val androidCveCount: Int = 0,
    val successfulSourcesLastRun: Int = 0,
    val freshSources: Int = 0,
    val totalSources: Int = 5
)

sealed class AutonomousUpdateResult {
    data class Success(val info: AutonomousIntelInfo, val changedSources: Int) : AutonomousUpdateResult()
    data class Partial(val info: AutonomousIntelInfo, val successfulSources: Int, val failedSources: Int, val changedSources: Int) : AutonomousUpdateResult()
    data object NoSourceAvailable : AutonomousUpdateResult()
}
