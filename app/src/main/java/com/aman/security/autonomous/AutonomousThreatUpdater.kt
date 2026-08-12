package com.aman.security.autonomous

import android.content.Context
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.scanner.UrlScanner

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
                    downloadedBytes = downloaded.coerceAtLeast(0L),
                    totalBytes = totalBytes,
                    sourceFinished = finished,
                    sourceSucceeded = succeeded
                )
            )
        }

        fun runSource(index: Int, key: String, block: ((Long, Long) -> Unit) -> Boolean) {
            report(key, index)
            var succeeded = false
            try {
                val changedNow = block { downloaded, total -> report(key, index, downloaded, total) }
                successfulSourceKeys += key
                succeeded = true
                if (changedNow) changed++
            } catch (_: Exception) {
                failedSourceKeys += key
            } finally {
                completedSources++
                report(key, index, finished = true, succeeded = succeeded)
            }
        }

        runSource(1, AutonomousThreatStore.SOURCE_MALWARE) { progress -> updateMalwareHashes(progress) }
        runSource(2, AutonomousThreatStore.SOURCE_PHISH_PRIMARY) { progress ->
            updatePhishing(
                AutonomousThreatStore.IndexKind.PHISHING_PRIMARY,
                PRIMARY_PHISH,
                "phish_primary",
                AutonomousThreatStore.SOURCE_PHISH_PRIMARY,
                progress
            )
        }
        runSource(3, AutonomousThreatStore.SOURCE_PHISH_COMMUNITY) { progress ->
            updatePhishing(
                AutonomousThreatStore.IndexKind.PHISHING_COMMUNITY,
                COMMUNITY_PHISH,
                "phish_community",
                AutonomousThreatStore.SOURCE_PHISH_COMMUNITY,
                progress
            )
        }
        runSource(4, AutonomousThreatStore.SOURCE_MALWARE_URLS) { progress -> updateMalwareUrls(progress) }
        runSource(5, AutonomousThreatStore.SOURCE_C2) { progress -> updateC2(progress) }

        val androidIndex = 6
        report(AutonomousThreatStore.SOURCE_ANDROID_BULLETIN, androidIndex)
        var androidSucceeded = false
        try {
            val bulletin = updateAndroidBulletin { downloaded, total ->
                report(AutonomousThreatStore.SOURCE_ANDROID_BULLETIN, androidIndex, downloaded, total)
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

    private fun updateMalwareHashes(progress: (Long, Long) -> Unit): Boolean {
        val response = http.get(MALWARE_BAZAAR_ANDROID, 4 * 1024 * 1024, "text/html", "malware_android", progress)
        if (response.notModified) return false
        val hashes = AutonomousThreatParsers.malwareBazaarAndroidHashes(requireNotNull(response.bytes).toString(Charsets.UTF_8))
        AutonomousFeedPolicy.validateCount(AutonomousThreatStore.SOURCE_MALWARE, hashes.size)
        return store.mergeFileHashes(hashes)
    }

    private fun updatePhishing(
        kind: AutonomousThreatStore.IndexKind,
        url: String,
        cacheKey: String,
        sourceKey: String,
        progress: (Long, Long) -> Unit
    ): Boolean {
        val response = http.get(url, 24 * 1024 * 1024, "application/json, text/plain", cacheKey, progress)
        if (response.notModified) return false
        val hosts = AutonomousThreatParsers.phishingHosts(requireNotNull(response.bytes).toString(Charsets.UTF_8))
        AutonomousFeedPolicy.validateCount(sourceKey, hosts.size)
        val hashes = hosts.asSequence().map(UrlScanner::sha256).toList()
        return store.replaceHashes(kind, hashes, minCount = AutonomousFeedPolicy.forKey(sourceKey).minEntries, shrinkFloor = 0.25)
    }

    private fun updateMalwareUrls(progress: (Long, Long) -> Unit): Boolean {
        val response = http.get(URLHAUS_URLS, 32 * 1024 * 1024, "text/plain", "urlhaus_malware_urls", progress)
        if (response.notModified) return false
        val hosts = AutonomousThreatParsers.urlhausHosts(requireNotNull(response.bytes).toString(Charsets.UTF_8))
        AutonomousFeedPolicy.validateCount(AutonomousThreatStore.SOURCE_MALWARE_URLS, hosts.size)
        val hashes = hosts.asSequence().map(UrlScanner::sha256).toList()
        return store.replaceHashes(
            AutonomousThreatStore.IndexKind.MALWARE_URL_HOSTS,
            hashes,
            minCount = AutonomousFeedPolicy.malwareUrls.minEntries,
            shrinkFloor = 0.20
        )
    }

    private fun updateC2(progress: (Long, Long) -> Unit): Boolean {
        val response = http.get(FEODO_RECOMMENDED, 2 * 1024 * 1024, "application/json", "feodo_c2", progress)
        if (response.notModified) return false
        val ips = AutonomousThreatParsers.feodoIps(requireNotNull(response.bytes).toString(Charsets.UTF_8))
        AutonomousFeedPolicy.validateCount(AutonomousThreatStore.SOURCE_C2, ips.size)
        return store.replaceHashes(
            AutonomousThreatStore.IndexKind.C2_HOSTS,
            ips.map(UrlScanner::sha256),
            minCount = AutonomousFeedPolicy.c2.minEntries,
            shrinkFloor = 0.10
        )
    }

    private fun updateAndroidBulletin(progress: (Long, Long) -> Unit): Triple<String, Int, Boolean> {
        val overview = http.get(ANDROID_OVERVIEW, 2 * 1024 * 1024, "text/html", "android_overview", progress)
        val oldInfo = store.info()
        if (overview.notModified) {
            val patch = oldInfo.latestAndroidSecurityPatch ?: throw java.io.IOException("No cached Android bulletin")
            return Triple(patch, oldInfo.androidCveCount, false)
        }
        val overviewText = requireNotNull(overview.bytes).toString(Charsets.UTF_8)
        val patch = AutonomousThreatParsers.latestAndroidPatch(overviewText) ?: throw java.io.IOException("Patch level missing")
        val monthStart = patch.substring(0, 7) + "-01"
        val bulletinUrl = "https://source.android.com/docs/security/bulletin/$monthStart?hl=en"
        val bulletin = http.get(bulletinUrl, 4 * 1024 * 1024, "text/html", "android_bulletin_$monthStart", progress)
        val cveChanged: Boolean
        val count: Int
        if (bulletin.notModified) {
            count = oldInfo.androidCveCount
            cveChanged = false
        } else {
            val cves = AutonomousThreatParsers.cves(requireNotNull(bulletin.bytes).toString(Charsets.UTF_8))
            AutonomousFeedPolicy.validateCount(AutonomousThreatStore.SOURCE_ANDROID_BULLETIN, cves.size)
            count = cves.size
            cveChanged = store.replaceAndroidCves(cves)
        }
        val changed = oldInfo.latestAndroidSecurityPatch != patch || oldInfo.androidCveCount != count || cveChanged
        return Triple(patch, count, changed)
    }

    companion object {
        val TOTAL_SOURCES: Int = AutonomousFeedPolicy.all.size
        private const val MALWARE_BAZAAR_ANDROID = "https://bazaar.abuse.ch/browse/tag/Android/"
        private const val PRIMARY_PHISH = "https://api.destroy.tools/v1/feed/primary_active"
        private const val COMMUNITY_PHISH = "https://api.destroy.tools/v1/feed/community_active"
        private const val URLHAUS_URLS = "https://urlhaus.abuse.ch/downloads/text/"
        private const val FEODO_RECOMMENDED = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        private const val ANDROID_OVERVIEW = "https://source.android.com/docs/security/bulletin/asb-overview?hl=en"
    }
}
