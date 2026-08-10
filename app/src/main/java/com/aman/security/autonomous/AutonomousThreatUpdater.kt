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

    fun update(): AutonomousUpdateResult {
        var successful = 0
        var changed = 0
        var latestPatch: String? = null
        var cveCount: Int? = null
        val successfulSourceKeys = linkedSetOf<String>()

        sourceRun { updateMalwareHashes() }.also { if (it.first) { successful++; successfulSourceKeys += AutonomousThreatStore.SOURCE_MALWARE }; if (it.second) changed++ }
        sourceRun { updatePhishing(AutonomousThreatStore.IndexKind.PHISHING_PRIMARY, PRIMARY_PHISH, "phish_primary") }.also { if (it.first) { successful++; successfulSourceKeys += AutonomousThreatStore.SOURCE_PHISH_PRIMARY }; if (it.second) changed++ }
        sourceRun { updatePhishing(AutonomousThreatStore.IndexKind.PHISHING_COMMUNITY, COMMUNITY_PHISH, "phish_community") }.also { if (it.first) { successful++; successfulSourceKeys += AutonomousThreatStore.SOURCE_PHISH_COMMUNITY }; if (it.second) changed++ }
        sourceRun { updateC2() }.also { if (it.first) { successful++; successfulSourceKeys += AutonomousThreatStore.SOURCE_C2 }; if (it.second) changed++ }

        val bulletin = runCatching { updateAndroidBulletin() }.getOrNull()
        if (bulletin != null) {
            successful++
            successfulSourceKeys += AutonomousThreatStore.SOURCE_ANDROID_BULLETIN
            latestPatch = bulletin.first
            cveCount = bulletin.second
            if (bulletin.third) changed++
        }

        if (successful == 0) return AutonomousUpdateResult.NoSourceAvailable
        store.updateState(
            lastSuccess = System.currentTimeMillis(),
            successfulSources = successful,
            successfulSourceKeys = successfulSourceKeys,
            latestPatch = latestPatch,
            cveCount = cveCount
        )
        database.reloadAutonomous()
        val info = store.info()
        return if (successful == TOTAL_SOURCES) AutonomousUpdateResult.Success(info, changed)
        else AutonomousUpdateResult.Partial(info, successful, TOTAL_SOURCES - successful, changed)
    }

    private fun sourceRun(block: () -> Boolean): Pair<Boolean, Boolean> = try { true to block() } catch (_: Exception) { false to false }

    private fun updateMalwareHashes(): Boolean {
        val response = http.get(MALWARE_BAZAAR_ANDROID, 4 * 1024 * 1024, "text/html", "malware_android")
        if (response.notModified) return false
        val hashes = AutonomousThreatParsers.malwareBazaarAndroidHashes(requireNotNull(response.bytes).toString(Charsets.UTF_8))
        require(hashes.isNotEmpty())
        return store.mergeFileHashes(hashes)
    }

    private fun updatePhishing(kind: AutonomousThreatStore.IndexKind, url: String, cacheKey: String): Boolean {
        val response = http.get(url, 24 * 1024 * 1024, "application/json, text/plain", cacheKey)
        if (response.notModified) return false
        val hosts = AutonomousThreatParsers.phishingHosts(requireNotNull(response.bytes).toString(Charsets.UTF_8))
        require(hosts.size >= 10)
        val hashes = hosts.asSequence().map(UrlScanner::sha256).take(MAX_PHISH_HOSTS).toList()
        return store.replaceHashes(kind, hashes, minCount = 10, shrinkFloor = 0.25)
    }

    private fun updateC2(): Boolean {
        val response = http.get(FEODO_RECOMMENDED, 2 * 1024 * 1024, "application/json", "feodo_c2")
        if (response.notModified) return false
        val ips = AutonomousThreatParsers.feodoIps(requireNotNull(response.bytes).toString(Charsets.UTF_8))
        require(ips.isNotEmpty())
        return store.replaceHashes(AutonomousThreatStore.IndexKind.C2_HOSTS, ips.map(UrlScanner::sha256), minCount = 1, shrinkFloor = 0.10)
    }

    private fun updateAndroidBulletin(): Triple<String, Int, Boolean> {
        val overview = http.get(ANDROID_OVERVIEW, 2 * 1024 * 1024, "text/html", "android_overview")
        val oldInfo = store.info()
        if (overview.notModified) {
            val patch = oldInfo.latestAndroidSecurityPatch ?: throw java.io.IOException("No cached Android bulletin")
            return Triple(patch, oldInfo.androidCveCount, false)
        }
        val overviewText = requireNotNull(overview.bytes).toString(Charsets.UTF_8)
        val patch = AutonomousThreatParsers.latestAndroidPatch(overviewText) ?: throw java.io.IOException("Patch level missing")
        val monthStart = patch.substring(0, 7) + "-01"
        val bulletinUrl = "https://source.android.com/docs/security/bulletin/$monthStart?hl=en"
        val bulletin = http.get(bulletinUrl, 4 * 1024 * 1024, "text/html", "android_bulletin_$monthStart")
        val cveChanged: Boolean
        val count: Int
        if (bulletin.notModified) {
            count = oldInfo.androidCveCount
            cveChanged = false
        } else {
            val cves = AutonomousThreatParsers.cves(requireNotNull(bulletin.bytes).toString(Charsets.UTF_8))
            count = cves.size
            cveChanged = store.replaceAndroidCves(cves)
        }
        val changed = oldInfo.latestAndroidSecurityPatch != patch || oldInfo.androidCveCount != count || cveChanged
        return Triple(patch, count, changed)
    }

    companion object {
        const val TOTAL_SOURCES = 5
        private const val MAX_PHISH_HOSTS = 250_000
        private const val MALWARE_BAZAAR_ANDROID = "https://bazaar.abuse.ch/browse/tag/Android/"
        private const val PRIMARY_PHISH = "https://api.destroy.tools/v1/feed/primary_active"
        private const val COMMUNITY_PHISH = "https://api.destroy.tools/v1/feed/community_active"
        private const val FEODO_RECOMMENDED = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        private const val ANDROID_OVERVIEW = "https://source.android.com/docs/security/bulletin/asb-overview?hl=en"
    }
}
