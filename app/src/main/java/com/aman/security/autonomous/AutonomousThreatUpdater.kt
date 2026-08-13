package com.aman.security.autonomous

import android.content.Context
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.scanner.UrlScanner

private typealias SourceProgress = (phase: AutonomousUpdatePhase, phaseProgress: Int, downloaded: Long, totalBytes: Long) -> Unit

class AutonomousThreatUpdater(
    context: Context,
    private val database: SignatureDatabase = SignatureDatabase(context)
) {
    private val store = database.autonomousStore
    private val http = AutonomousThreatHttpClient(context)

    fun update(onProgress: ((AutonomousUpdateProgress) -> Unit)? = null): AutonomousUpdateResult {
        var changed = 0
        var latestPatch: String? = null
        var cveCount: Int? = null
        val successfulSourceKeys = linkedSetOf<String>()
        val failedSourceKeys = linkedSetOf<String>()
        val attemptAt = System.currentTimeMillis()
        var completedSources = 0

        fun report(
            key: String,
            index: Int,
            phase: AutonomousUpdatePhase = AutonomousUpdatePhase.CONNECTING,
            phaseProgress: Int = 0,
            downloaded: Long = 0L,
            totalBytes: Long = -1L,
            finished: Boolean = false,
            succeeded: Boolean? = null
        ) {
            onProgress?.invoke(
                AutonomousUpdateProgress(
                    sourceKey = key,
                    sourceIndex = index,
                    totalSources = TOTAL_SOURCES,
                    completedSources = completedSources,
                    phase = phase,
                    phaseProgress = phaseProgress.coerceIn(0, 100),
                    downloadedBytes = downloaded.coerceAtLeast(0L),
                    totalBytes = totalBytes,
                    sourceFinished = finished,
                    sourceSucceeded = succeeded
                )
            )
        }

        fun runSource(index: Int, key: String, block: (SourceProgress) -> Boolean) {
            report(key, index, phase = AutonomousUpdatePhase.CONNECTING)
            var succeeded = false
            try {
                val changedNow = block { phase, phaseProgress, downloaded, total ->
                    report(key, index, phase, phaseProgress, downloaded, total)
                }
                successfulSourceKeys += key
                succeeded = true
                if (changedNow) changed++
            } catch (_: Exception) {
                // A failed or slow source must never hold the entire protection update hostage.
                // Last-known-good data remains intact and the updater immediately continues.
                failedSourceKeys += key
            } finally {
                completedSources++
                report(
                    key = key,
                    index = index,
                    phase = AutonomousUpdatePhase.APPLYING,
                    phaseProgress = 100,
                    finished = true,
                    succeeded = succeeded
                )
            }
        }

        runSource(1, AutonomousThreatStore.SOURCE_MALWARE) { progress -> updateMalwareHashes(progress) }

        // Fetch the compact first-party OpenPhish feed before the larger aggregate feeds so Aman
        // can establish live phishing coverage quickly even if a later provider is slow or down.
        runSource(2, AutonomousThreatStore.SOURCE_PHISH_OPENPHISH) { progress -> updateOpenPhish(progress) }
        runSource(3, AutonomousThreatStore.SOURCE_PHISH_PRIMARY) { progress ->
            updatePhishing(
                AutonomousThreatStore.IndexKind.PHISHING_PRIMARY,
                PRIMARY_PHISH,
                "phish_primary",
                AutonomousThreatStore.SOURCE_PHISH_PRIMARY,
                progress
            )
        }
        runSource(4, AutonomousThreatStore.SOURCE_PHISH_COMMUNITY) { progress ->
            updatePhishing(
                AutonomousThreatStore.IndexKind.PHISHING_COMMUNITY,
                COMMUNITY_PHISH,
                "phish_community",
                AutonomousThreatStore.SOURCE_PHISH_COMMUNITY,
                progress
            )
        }
        runSource(5, AutonomousThreatStore.SOURCE_MALWARE_URLS) { progress -> updateMalwareUrls(progress) }
        runSource(6, AutonomousThreatStore.SOURCE_C2) { progress -> updateC2(progress) }

        val androidIndex = 7
        report(AutonomousThreatStore.SOURCE_ANDROID_BULLETIN, androidIndex, phase = AutonomousUpdatePhase.CONNECTING)
        var androidSucceeded = false
        try {
            val bulletin = updateAndroidBulletin { phase, phaseProgress, downloaded, total ->
                report(
                    AutonomousThreatStore.SOURCE_ANDROID_BULLETIN,
                    androidIndex,
                    phase,
                    phaseProgress,
                    downloaded,
                    total
                )
            }
            successfulSourceKeys += AutonomousThreatStore.SOURCE_ANDROID_BULLETIN
            androidSucceeded = true
            latestPatch = bulletin.first
            cveCount = bulletin.second
            if (bulletin.third) changed++
        } catch (_: Exception) {
            failedSourceKeys += AutonomousThreatStore.SOURCE_ANDROID_BULLETIN
        } finally {
            completedSources++
            report(
                AutonomousThreatStore.SOURCE_ANDROID_BULLETIN,
                androidIndex,
                phase = AutonomousUpdatePhase.APPLYING,
                phaseProgress = 100,
                finished = true,
                succeeded = androidSucceeded
            )
        }

        // Persist source-level health even on a total outage. Last-known-good indicator files
        // stay untouched for failed sources, while transient URL/C2 entries expire by TTL.
        store.recordRun(
            attemptAt = attemptAt,
            successfulSourceKeys = successfulSourceKeys,
            failedSourceKeys = failedSourceKeys,
            latestPatch = latestPatch,
            cveCount = cveCount
        )
        database.reloadAutonomous()
        val info = store.info()
        if (successfulSourceKeys.isEmpty()) return AutonomousUpdateResult.NoSourceAvailable
        return if (successfulSourceKeys.size == TOTAL_SOURCES) {
            AutonomousUpdateResult.Success(info, changed)
        } else {
            AutonomousUpdateResult.Partial(info, successfulSourceKeys.size, failedSourceKeys.size, changed)
        }
    }

    private fun updateMalwareHashes(progress: SourceProgress): Boolean {
        val response = http.get(
            MALWARE_BAZAAR_ANDROID,
            4 * 1024 * 1024,
            "text/html",
            "malware_android",
            onProgress = { downloaded, total -> progress(AutonomousUpdatePhase.DOWNLOADING, transferPercent(downloaded, total), downloaded, total) },
            maxDurationMs = SMALL_SOURCE_DEADLINE_MS
        )
        if (response.notModified) {
            progress(AutonomousUpdatePhase.APPLYING, 100, 0L, 0L)
            return false
        }
        val bytes = requireNotNull(response.bytes)
        progress(AutonomousUpdatePhase.PARSING, 10, bytes.size.toLong(), bytes.size.toLong())
        val hashes = AutonomousThreatParsers.malwareBazaarAndroidHashes(bytes.toString(Charsets.UTF_8))
        progress(AutonomousUpdatePhase.PARSING, 100, bytes.size.toLong(), bytes.size.toLong())
        AutonomousFeedPolicy.validateCount(AutonomousThreatStore.SOURCE_MALWARE, hashes.size)
        progress(AutonomousUpdatePhase.APPLYING, 40, bytes.size.toLong(), bytes.size.toLong())
        val changed = store.mergeFileHashes(hashes)
        progress(AutonomousUpdatePhase.APPLYING, 100, bytes.size.toLong(), bytes.size.toLong())
        return changed
    }

    private fun updatePhishing(
        kind: AutonomousThreatStore.IndexKind,
        url: String,
        cacheKey: String,
        sourceKey: String,
        progress: SourceProgress
    ): Boolean {
        val response = http.get(
            url,
            24 * 1024 * 1024,
            "application/json, text/plain",
            cacheKey,
            onProgress = { downloaded, total -> progress(AutonomousUpdatePhase.DOWNLOADING, transferPercent(downloaded, total), downloaded, total) },
            maxDurationMs = PHISHING_SOURCE_DEADLINE_MS
        )
        if (response.notModified) {
            progress(AutonomousUpdatePhase.APPLYING, 100, 0L, 0L)
            return false
        }
        val bytes = requireNotNull(response.bytes)
        val text = bytes.toString(Charsets.UTF_8)
        val indicators = AutonomousThreatParsers.phishingIndicators(text) { percent ->
            progress(AutonomousUpdatePhase.PARSING, percent, bytes.size.toLong(), bytes.size.toLong())
        }
        val hashes = hashIndicators(indicators, progress, bytes.size.toLong())
        AutonomousFeedPolicy.validateCount(sourceKey, hashes.size)
        progress(AutonomousUpdatePhase.APPLYING, 20, bytes.size.toLong(), bytes.size.toLong())
        val changed = store.replaceHashes(
            kind,
            hashes,
            minCount = AutonomousFeedPolicy.forKey(sourceKey).minEntries,
            shrinkFloor = 0.25
        )
        progress(AutonomousUpdatePhase.APPLYING, 100, bytes.size.toLong(), bytes.size.toLong())
        return changed
    }

    private fun updateOpenPhish(progress: SourceProgress): Boolean {
        val response = http.get(
            OPENPHISH_COMMUNITY,
            8 * 1024 * 1024,
            "text/plain",
            "openphish_community",
            onProgress = { downloaded, total -> progress(AutonomousUpdatePhase.DOWNLOADING, transferPercent(downloaded, total), downloaded, total) },
            maxDurationMs = OPENPHISH_SOURCE_DEADLINE_MS
        )
        if (response.notModified) {
            progress(AutonomousUpdatePhase.APPLYING, 100, 0L, 0L)
            return false
        }
        val bytes = requireNotNull(response.bytes)
        val indicators = AutonomousThreatParsers.phishingIndicators(bytes.toString(Charsets.UTF_8)) { percent ->
            progress(AutonomousUpdatePhase.PARSING, percent, bytes.size.toLong(), bytes.size.toLong())
        }
        val hashes = hashIndicators(indicators, progress, bytes.size.toLong())
        AutonomousFeedPolicy.validateCount(AutonomousThreatStore.SOURCE_PHISH_OPENPHISH, hashes.size)
        progress(AutonomousUpdatePhase.APPLYING, 20, bytes.size.toLong(), bytes.size.toLong())
        val changed = store.replaceHashes(
            AutonomousThreatStore.IndexKind.PHISHING_OPENPHISH,
            hashes,
            minCount = AutonomousFeedPolicy.phishingOpenPhish.minEntries,
            shrinkFloor = 0.20
        )
        progress(AutonomousUpdatePhase.APPLYING, 100, bytes.size.toLong(), bytes.size.toLong())
        return changed
    }

    private fun updateMalwareUrls(progress: SourceProgress): Boolean {
        val response = http.get(
            URLHAUS_URLS,
            32 * 1024 * 1024,
            "text/plain",
            "urlhaus_malware_urls",
            onProgress = { downloaded, total -> progress(AutonomousUpdatePhase.DOWNLOADING, transferPercent(downloaded, total), downloaded, total) },
            maxDurationMs = LARGE_SOURCE_DEADLINE_MS
        )
        if (response.notModified) {
            progress(AutonomousUpdatePhase.APPLYING, 100, 0L, 0L)
            return false
        }
        val bytes = requireNotNull(response.bytes)
        val indicators = AutonomousThreatParsers.urlhausIndicators(bytes.toString(Charsets.UTF_8)) { percent ->
            progress(AutonomousUpdatePhase.PARSING, percent, bytes.size.toLong(), bytes.size.toLong())
        }
        val hashes = hashIndicators(indicators, progress, bytes.size.toLong())
        AutonomousFeedPolicy.validateCount(AutonomousThreatStore.SOURCE_MALWARE_URLS, hashes.size)
        progress(AutonomousUpdatePhase.APPLYING, 20, bytes.size.toLong(), bytes.size.toLong())
        val changed = store.replaceHashes(
            AutonomousThreatStore.IndexKind.MALWARE_URL_HOSTS,
            hashes,
            minCount = AutonomousFeedPolicy.malwareUrls.minEntries,
            shrinkFloor = 0.20
        )
        progress(AutonomousUpdatePhase.APPLYING, 100, bytes.size.toLong(), bytes.size.toLong())
        return changed
    }

    private fun updateC2(progress: SourceProgress): Boolean {
        val response = http.get(
            FEODO_RECOMMENDED,
            2 * 1024 * 1024,
            "application/json",
            "feodo_c2",
            onProgress = { downloaded, total -> progress(AutonomousUpdatePhase.DOWNLOADING, transferPercent(downloaded, total), downloaded, total) },
            maxDurationMs = SMALL_SOURCE_DEADLINE_MS
        )
        if (response.notModified) {
            progress(AutonomousUpdatePhase.APPLYING, 100, 0L, 0L)
            return false
        }
        val bytes = requireNotNull(response.bytes)
        progress(AutonomousUpdatePhase.PARSING, 15, bytes.size.toLong(), bytes.size.toLong())
        val ips = AutonomousThreatParsers.feodoIps(bytes.toString(Charsets.UTF_8))
        progress(AutonomousUpdatePhase.PARSING, 100, bytes.size.toLong(), bytes.size.toLong())
        AutonomousFeedPolicy.validateCount(AutonomousThreatStore.SOURCE_C2, ips.size)
        val hashes = linkedSetOf<String>()
        val total = ips.size.coerceAtLeast(1)
        var lastIndexPercent = -2
        ips.forEachIndexed { index, ip ->
            hashes += UrlScanner.sha256(ip)
            val percent = (((index + 1).toLong() * 100L) / total.toLong()).toInt().coerceIn(0, 100)
            if (percent >= lastIndexPercent + 2 || percent == 100) {
                lastIndexPercent = percent
                progress(AutonomousUpdatePhase.INDEXING, percent, bytes.size.toLong(), bytes.size.toLong())
            }
        }
        progress(AutonomousUpdatePhase.APPLYING, 20, bytes.size.toLong(), bytes.size.toLong())
        val changed = store.replaceHashes(
            AutonomousThreatStore.IndexKind.C2_HOSTS,
            hashes,
            minCount = AutonomousFeedPolicy.c2.minEntries,
            shrinkFloor = 0.10
        )
        progress(AutonomousUpdatePhase.APPLYING, 100, bytes.size.toLong(), bytes.size.toLong())
        return changed
    }

    private fun updateAndroidBulletin(progress: SourceProgress): Triple<String, Int, Boolean> {
        val overview = http.get(
            ANDROID_OVERVIEW,
            2 * 1024 * 1024,
            "text/html",
            "android_overview",
            onProgress = { downloaded, total -> progress(AutonomousUpdatePhase.DOWNLOADING, transferPercent(downloaded, total), downloaded, total) },
            maxDurationMs = SMALL_SOURCE_DEADLINE_MS
        )
        val oldInfo = store.info()
        if (overview.notModified) {
            val patch = oldInfo.latestAndroidSecurityPatch ?: throw java.io.IOException("No cached Android bulletin")
            progress(AutonomousUpdatePhase.APPLYING, 100, 0L, 0L)
            return Triple(patch, oldInfo.androidCveCount, false)
        }
        val overviewBytes = requireNotNull(overview.bytes)
        progress(AutonomousUpdatePhase.PARSING, 20, overviewBytes.size.toLong(), overviewBytes.size.toLong())
        val overviewText = overviewBytes.toString(Charsets.UTF_8)
        val patch = AutonomousThreatParsers.latestAndroidPatch(overviewText) ?: throw java.io.IOException("Patch level missing")
        progress(AutonomousUpdatePhase.PARSING, 50, overviewBytes.size.toLong(), overviewBytes.size.toLong())
        val monthStart = patch.substring(0, 7) + "-01"
        val bulletinUrl = "https://source.android.com/docs/security/bulletin/$monthStart?hl=en"
        val bulletin = http.get(
            bulletinUrl,
            4 * 1024 * 1024,
            "text/html",
            "android_bulletin_$monthStart",
            onProgress = { downloaded, total -> progress(AutonomousUpdatePhase.DOWNLOADING, transferPercent(downloaded, total), downloaded, total) },
            maxDurationMs = SMALL_SOURCE_DEADLINE_MS
        )
        val cveChanged: Boolean
        val count: Int
        if (bulletin.notModified) {
            count = oldInfo.androidCveCount
            cveChanged = false
        } else {
            val bulletinBytes = requireNotNull(bulletin.bytes)
            progress(AutonomousUpdatePhase.PARSING, 65, bulletinBytes.size.toLong(), bulletinBytes.size.toLong())
            val cves = AutonomousThreatParsers.cves(bulletinBytes.toString(Charsets.UTF_8))
            progress(AutonomousUpdatePhase.PARSING, 100, bulletinBytes.size.toLong(), bulletinBytes.size.toLong())
            AutonomousFeedPolicy.validateCount(AutonomousThreatStore.SOURCE_ANDROID_BULLETIN, cves.size)
            count = cves.size
            progress(AutonomousUpdatePhase.APPLYING, 30, bulletinBytes.size.toLong(), bulletinBytes.size.toLong())
            cveChanged = store.replaceAndroidCves(cves)
        }
        progress(AutonomousUpdatePhase.APPLYING, 100, 0L, 0L)
        val changed = oldInfo.latestAndroidSecurityPatch != patch || oldInfo.androidCveCount != count || cveChanged
        return Triple(patch, count, changed)
    }

    private fun hashIndicators(
        indicators: AutonomousThreatParsers.UrlIndicators,
        progress: SourceProgress,
        downloadedBytes: Long
    ): List<String> {
        val hashes = linkedSetOf<String>()
        val total = (indicators.urls.size + indicators.hosts.size).coerceAtLeast(1)
        var completed = 0
        var lastIndexPercent = -2
        fun add(value: String) {
            hashes += UrlScanner.sha256(value)
            completed++
            val percent = ((completed.toLong() * 100L) / total.toLong()).toInt().coerceIn(0, 100)
            if (percent >= lastIndexPercent + 2 || percent == 100) {
                lastIndexPercent = percent
                progress(AutonomousUpdatePhase.INDEXING, percent, downloadedBytes, downloadedBytes)
            }
        }
        indicators.urls.forEach(::add)
        indicators.hosts.forEach(::add)
        progress(AutonomousUpdatePhase.INDEXING, 100, downloadedBytes, downloadedBytes)
        return hashes.toList()
    }

    private fun transferPercent(downloaded: Long, total: Long): Int =
        if (total > 0L) ((downloaded.coerceAtLeast(0L) * 100L) / total).toInt().coerceIn(0, 100) else 0

    companion object {
        val TOTAL_SOURCES: Int = AutonomousFeedPolicy.all.size
        private const val MALWARE_BAZAAR_ANDROID = "https://bazaar.abuse.ch/browse/tag/Android/"
        private const val PRIMARY_PHISH = "https://api.destroy.tools/v1/feed/primary_active"
        private const val COMMUNITY_PHISH = "https://api.destroy.tools/v1/feed/community_active"
        private const val OPENPHISH_COMMUNITY = "https://openphish.com/feed.txt"
        private const val URLHAUS_URLS = "https://urlhaus.abuse.ch/downloads/text/"
        private const val FEODO_RECOMMENDED = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        private const val ANDROID_OVERVIEW = "https://source.android.com/docs/security/bulletin/asb-overview?hl=en"

        private const val SMALL_SOURCE_DEADLINE_MS = 45_000L
        private const val OPENPHISH_SOURCE_DEADLINE_MS = 60_000L
        private const val PHISHING_SOURCE_DEADLINE_MS = 75_000L
        private const val LARGE_SOURCE_DEADLINE_MS = 120_000L
    }
}
