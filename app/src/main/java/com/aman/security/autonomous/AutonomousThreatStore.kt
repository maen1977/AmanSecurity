package com.aman.security.autonomous

import android.content.Context
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.ThreatSignature
import com.aman.security.scanner.UrlIndicatorKind
import com.aman.security.scanner.UrlThreatClassification
import com.aman.security.scanner.UrlThreatIndicator
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.TimeUnit

class AutonomousThreatStore(context: Context) {
    private val directory = File(context.filesDir, "autonomous-intel-v1").apply { mkdirs() }
    private val stateFile = File(directory, "state.json")
    private val fileHashes = File(directory, "malware_files.sha256")
    private val phishPrimary = File(directory, "phishing_primary.sha256")
    private val phishCommunity = File(directory, "phishing_community.sha256")
    private val malwareUrlHosts = File(directory, "malware_url_hosts.sha256")
    private val c2Hosts = File(directory, "c2_hosts.sha256")
    private val androidCves = File(directory, "android_cves.txt")

    @Volatile private var malwareIndex = FixedSha256Index.load(fileHashes)
    @Volatile private var phishPrimaryIndex = FixedSha256Index.load(phishPrimary)
    @Volatile private var phishCommunityIndex = FixedSha256Index.load(phishCommunity)
    @Volatile private var malwareUrlIndex = FixedSha256Index.load(malwareUrlHosts)
    @Volatile private var c2Index = FixedSha256Index.load(c2Hosts)
    @Volatile private var sourceLastSuccess = readSourceSuccesses()
    @Volatile private var sourceConsecutiveFailures = readSourceFailures()

    fun findFile(sha256: String): ThreatSignature? {
        val h = normalizeSha(sha256) ?: return null
        // File SHA-256 indicators describe immutable file content, so a previously accepted
        // malicious file hash remains useful even if the source is temporarily unavailable.
        return if (malwareIndex.contains(h)) ThreatSignature(h, "AUTO_MALWARE_HASH", ScanClassification.KNOWN_THREAT) else null
    }

    fun findUrl(kind: UrlIndicatorKind, sha256: String): UrlThreatIndicator? {
        if (kind != UrlIndicatorKind.HOST) return null
        val h = normalizeSha(sha256) ?: return null
        val now = System.currentTimeMillis()
        return when {
            phishPrimaryIndex.contains(h) && sourceFresh(SOURCE_PHISH_PRIMARY, now, AutonomousFeedPolicy.phishingPrimary.lookupTtlMs) ->
                UrlThreatIndicator(kind, h, "AUTO_PHISHING_PRIMARY", UrlThreatClassification.PHISHING)
            malwareUrlIndex.contains(h) && sourceFresh(SOURCE_MALWARE_URLS, now, AutonomousFeedPolicy.malwareUrls.lookupTtlMs) ->
                UrlThreatIndicator(kind, h, "AUTO_URLHAUS_MALWARE", UrlThreatClassification.MALWARE)
            c2Index.contains(h) && sourceFresh(SOURCE_C2, now, AutonomousFeedPolicy.c2.lookupTtlMs) ->
                UrlThreatIndicator(kind, h, "AUTO_C2_HOST", UrlThreatClassification.MALWARE)
            phishCommunityIndex.contains(h) && sourceFresh(SOURCE_PHISH_COMMUNITY, now, AutonomousFeedPolicy.phishingCommunity.lookupTtlMs) ->
                UrlThreatIndicator(kind, h, "AUTO_PHISHING_COMMUNITY", UrlThreatClassification.SUSPICIOUS_SOURCE)
            else -> null
        }
    }

    @Synchronized fun reload() {
        malwareIndex = FixedSha256Index.load(fileHashes)
        phishPrimaryIndex = FixedSha256Index.load(phishPrimary)
        phishCommunityIndex = FixedSha256Index.load(phishCommunity)
        malwareUrlIndex = FixedSha256Index.load(malwareUrlHosts)
        c2Index = FixedSha256Index.load(c2Hosts)
        sourceLastSuccess = readSourceSuccesses()
        sourceConsecutiveFailures = readSourceFailures()
    }

    fun info(): AutonomousIntelInfo {
        val state = readState()
        val now = System.currentTimeMillis()
        val health = AutonomousFeedPolicy.all.map { descriptor ->
            val last = sourceLastSuccess[descriptor.key] ?: 0L
            val fresh = sourceFresh(descriptor.key, now, descriptor.statusFreshMs)
            AutonomousSourceHealth(
                key = descriptor.key,
                trust = descriptor.trust,
                lastSuccessEpochMs = last,
                ageHours = if (last > 0L && now >= last) TimeUnit.MILLISECONDS.toHours(now - last) else null,
                fresh = fresh,
                itemCount = sourceItemCount(descriptor.key, state),
                consecutiveFailures = sourceConsecutiveFailures[descriptor.key] ?: 0
            )
        }
        return AutonomousIntelInfo(
            lastSuccessfulUpdateEpochMs = state.optLong("lastSuccessfulUpdateEpochMs", 0L),
            lastAttemptEpochMs = state.optLong("lastAttemptEpochMs", 0L),
            malwareFileHashes = malwareIndex.count,
            phishingHosts = phishPrimaryIndex.count + phishCommunityIndex.count,
            c2Hosts = c2Index.count,
            latestAndroidSecurityPatch = state.optString("latestAndroidSecurityPatch", "").takeIf { it.isNotBlank() },
            androidCveCount = state.optInt("androidCveCount", 0),
            successfulSourcesLastRun = state.optInt("successfulSourcesLastRun", 0),
            failedSourcesLastRun = state.optInt("failedSourcesLastRun", 0),
            freshSources = health.count { it.fresh },
            staleSources = health.count { !it.fresh },
            totalSources = health.size,
            sourceHealth = health
        )
    }

    fun readHashes(kind: IndexKind): Set<String> = indexFile(kind).takeIf(File::isFile)?.readLines()
        ?.asSequence()?.map(String::trim)?.filter { HASH.matches(it) }?.toCollection(linkedSetOf()) ?: emptySet()

    fun count(kind: IndexKind): Int = when (kind) {
        IndexKind.MALWARE_FILES -> malwareIndex.count
        IndexKind.PHISHING_PRIMARY -> phishPrimaryIndex.count
        IndexKind.PHISHING_COMMUNITY -> phishCommunityIndex.count
        IndexKind.MALWARE_URL_HOSTS -> malwareUrlIndex.count
        IndexKind.C2_HOSTS -> c2Index.count
    }

    @Synchronized fun replaceHashes(kind: IndexKind, hashes: Collection<String>, minCount: Int = 1, shrinkFloor: Double? = null): Boolean {
        val clean = hashes.asSequence().mapNotNull(::normalizeSha).distinct().sorted().toList()
        val sourceKey = sourceKey(kind)
        AutonomousFeedPolicy.validateCount(sourceKey, clean.size)
        require(clean.size >= minCount)
        val target = indexFile(kind)
        val oldCount = FixedSha256Index.load(target).count
        if (shrinkFloor != null && oldCount >= 100 && clean.size < (oldCount * shrinkFloor).toInt()) {
            throw IllegalArgumentException("Unexpected source shrink")
        }
        val newText = clean.joinToString(separator = "\n", postfix = "\n")
        if (target.isFile && target.readText() == newText) return false
        atomicWrite(target, newText.toByteArray(Charsets.US_ASCII))
        reload()
        return true
    }

    @Synchronized fun mergeFileHashes(newHashes: Collection<String>, maxEntries: Int = AutonomousFeedPolicy.malware.maxEntries): Boolean {
        val cleanNew = newHashes.asSequence().mapNotNull(::normalizeSha).distinct().toList()
        require(cleanNew.size >= AutonomousFeedPolicy.malware.minEntries)
        require(cleanNew.size <= AutonomousFeedPolicy.malware.maxEntries)
        val merged = linkedSetOf<String>()
        merged += readHashes(IndexKind.MALWARE_FILES)
        merged += cleanNew
        val bounded = if (merged.size <= maxEntries) merged else merged.toList().takeLast(maxEntries).toCollection(linkedSetOf())
        return replaceHashes(IndexKind.MALWARE_FILES, bounded, minCount = 1)
    }

    @Synchronized fun replaceAndroidCves(cves: Collection<String>): Boolean {
        val clean = cves.asSequence().map { it.trim().uppercase(Locale.ROOT) }
            .filter(CVE::matches).distinct().sorted().toList()
        AutonomousFeedPolicy.validateCount(SOURCE_ANDROID_BULLETIN, clean.size)
        val newText = if (clean.isEmpty()) "" else clean.joinToString(separator = "\n", postfix = "\n")
        if (androidCves.isFile && androidCves.readText() == newText) return false
        atomicWrite(androidCves, newText.toByteArray(Charsets.US_ASCII))
        return true
    }

    /** Records both successes and failures without replacing last-known-good indicator files. */
    @Synchronized fun recordRun(
        attemptAt: Long,
        successfulSourceKeys: Set<String>,
        failedSourceKeys: Set<String>,
        latestPatch: String? = null,
        cveCount: Int? = null
    ) {
        val state = readState()
        state.put("lastAttemptEpochMs", attemptAt)
        state.put("successfulSourcesLastRun", successfulSourceKeys.size)
        state.put("failedSourcesLastRun", failedSourceKeys.size)
        if (successfulSourceKeys.isNotEmpty()) state.put("lastSuccessfulUpdateEpochMs", attemptAt)

        successfulSourceKeys.filter(SOURCE_KEYS::contains).forEach { key ->
            state.put("source_${key}_lastSuccessEpochMs", attemptAt)
            state.put("source_${key}_consecutiveFailures", 0)
        }
        failedSourceKeys.filter(SOURCE_KEYS::contains).forEach { key ->
            val current = state.optInt("source_${key}_consecutiveFailures", 0)
            state.put("source_${key}_consecutiveFailures", (current + 1).coerceAtMost(999))
        }
        latestPatch?.let { current ->
            val old = state.optString("latestAndroidSecurityPatch", "")
            if (old.isBlank() || current >= old) state.put("latestAndroidSecurityPatch", current)
        }
        cveCount?.let { state.put("androidCveCount", it.coerceAtLeast(0)) }
        atomicWrite(stateFile, state.toString().toByteArray(Charsets.UTF_8))
        sourceLastSuccess = readSourceSuccesses()
        sourceConsecutiveFailures = readSourceFailures()
    }

    private fun readSourceSuccesses(): Map<String, Long> {
        val state = readState()
        return SOURCE_KEYS.associateWith { key -> state.optLong("source_${key}_lastSuccessEpochMs", 0L) }
    }

    private fun readSourceFailures(): Map<String, Int> {
        val state = readState()
        return SOURCE_KEYS.associateWith { key -> state.optInt("source_${key}_consecutiveFailures", 0) }
    }

    private fun sourceFresh(key: String, now: Long, ttlMs: Long): Boolean {
        val last = sourceLastSuccess[key] ?: 0L
        if (last <= 0L || now < last) return false
        return ttlMs == Long.MAX_VALUE || now - last <= ttlMs
    }

    enum class IndexKind { MALWARE_FILES, PHISHING_PRIMARY, PHISHING_COMMUNITY, MALWARE_URL_HOSTS, C2_HOSTS }

    private fun indexFile(kind: IndexKind): File = when (kind) {
        IndexKind.MALWARE_FILES -> fileHashes
        IndexKind.PHISHING_PRIMARY -> phishPrimary
        IndexKind.PHISHING_COMMUNITY -> phishCommunity
        IndexKind.MALWARE_URL_HOSTS -> malwareUrlHosts
        IndexKind.C2_HOSTS -> c2Hosts
    }

    private fun sourceKey(kind: IndexKind): String = when (kind) {
        IndexKind.MALWARE_FILES -> SOURCE_MALWARE
        IndexKind.PHISHING_PRIMARY -> SOURCE_PHISH_PRIMARY
        IndexKind.PHISHING_COMMUNITY -> SOURCE_PHISH_COMMUNITY
        IndexKind.MALWARE_URL_HOSTS -> SOURCE_MALWARE_URLS
        IndexKind.C2_HOSTS -> SOURCE_C2
    }

    private fun sourceItemCount(key: String, state: JSONObject): Int = when (key) {
        SOURCE_MALWARE -> malwareIndex.count
        SOURCE_PHISH_PRIMARY -> phishPrimaryIndex.count
        SOURCE_PHISH_COMMUNITY -> phishCommunityIndex.count
        SOURCE_MALWARE_URLS -> malwareUrlIndex.count
        SOURCE_C2 -> c2Index.count
        SOURCE_ANDROID_BULLETIN -> state.optInt("androidCveCount", 0)
        else -> 0
    }

    private fun readState(): JSONObject = runCatching { JSONObject(stateFile.readText()) }.getOrElse { JSONObject() }

    private fun atomicWrite(target: File, bytes: ByteArray) {
        val temp = File(directory, target.name + ".tmp")
        temp.outputStream().use { it.write(bytes); it.fdSyncCompat() }
        if (!temp.renameTo(target)) { target.delete(); check(temp.renameTo(target)) }
    }

    private fun java.io.FileOutputStream.fdSyncCompat() = runCatching { fd.sync() }.getOrNull()

    private fun normalizeSha(value: String): String? = value.trim().lowercase(Locale.ROOT).takeIf(HASH::matches)

    private class FixedSha256Index private constructor(private val bytes: ByteArray, val count: Int) {
        fun contains(hex: String): Boolean {
            if (!HASH.matches(hex)) return false
            var low = 0; var high = count - 1
            while (low <= high) {
                val mid = (low + high).ushr(1)
                val cmp = compareAt(mid, hex)
                if (cmp == 0) return true
                if (cmp < 0) low = mid + 1 else high = mid - 1
            }
            return false
        }
        private fun compareAt(index: Int, hex: String): Int {
            val offset = index * 65
            for (i in 0 until 64) {
                val a = bytes[offset + i].toInt() and 0xff
                val b = hex[i].code
                if (a != b) return a - b
            }
            return 0
        }
        companion object {
            fun load(file: File): FixedSha256Index {
                if (!file.isFile) return FixedSha256Index(ByteArray(0), 0)
                val data = runCatching { file.readBytes() }.getOrElse { return FixedSha256Index(ByteArray(0), 0) }
                if (data.isEmpty() || data.size % 65 != 0) return FixedSha256Index(ByteArray(0), 0)
                val count = data.size / 65
                for (i in 0 until count) {
                    val offset = i * 65
                    if (data[offset + 64] != '\n'.code.toByte()) return FixedSha256Index(ByteArray(0), 0)
                }
                return FixedSha256Index(data, count)
            }
        }
    }

    companion object {
        const val SOURCE_MALWARE = "malware"
        const val SOURCE_PHISH_PRIMARY = "phish_primary"
        const val SOURCE_PHISH_COMMUNITY = "phish_community"
        const val SOURCE_MALWARE_URLS = "malware_urls"
        const val SOURCE_C2 = "c2"
        const val SOURCE_ANDROID_BULLETIN = "android_bulletin"
        val SOURCE_KEYS = listOf(SOURCE_MALWARE, SOURCE_PHISH_PRIMARY, SOURCE_PHISH_COMMUNITY, SOURCE_MALWARE_URLS, SOURCE_C2, SOURCE_ANDROID_BULLETIN)
        private val HASH = Regex("^[a-f0-9]{64}$")
        private val CVE = Regex("^CVE-20\\d{2}-\\d{4,8}$")
        fun sha256(text: String): String = MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
