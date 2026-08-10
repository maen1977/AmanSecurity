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

class AutonomousThreatStore(context: Context) {
    private val directory = File(context.filesDir, "autonomous-intel-v1").apply { mkdirs() }
    private val stateFile = File(directory, "state.json")
    private val fileHashes = File(directory, "malware_files.sha256")
    private val phishPrimary = File(directory, "phishing_primary.sha256")
    private val phishCommunity = File(directory, "phishing_community.sha256")
    private val c2Hosts = File(directory, "c2_hosts.sha256")
    private val androidCves = File(directory, "android_cves.txt")

    @Volatile private var malwareIndex = FixedSha256Index.load(fileHashes)
    @Volatile private var phishPrimaryIndex = FixedSha256Index.load(phishPrimary)
    @Volatile private var phishCommunityIndex = FixedSha256Index.load(phishCommunity)
    @Volatile private var c2Index = FixedSha256Index.load(c2Hosts)
    @Volatile private var sourceLastSuccess = readSourceSuccesses()

    fun findFile(sha256: String): ThreatSignature? {
        val h = normalizeSha(sha256) ?: return null
        return if (malwareIndex.contains(h)) ThreatSignature(h, "AUTO_MALWARE_HASH", ScanClassification.KNOWN_THREAT) else null
    }

    fun findUrl(kind: UrlIndicatorKind, sha256: String): UrlThreatIndicator? {
        if (kind != UrlIndicatorKind.HOST) return null
        val h = normalizeSha(sha256) ?: return null
        val now = System.currentTimeMillis()
        return when {
            phishPrimaryIndex.contains(h) && sourceFresh(SOURCE_PHISH_PRIMARY, now, PHISHING_TTL_MS) ->
                UrlThreatIndicator(kind, h, "AUTO_PHISHING_PRIMARY", UrlThreatClassification.PHISHING)
            c2Index.contains(h) && sourceFresh(SOURCE_C2, now, C2_TTL_MS) ->
                UrlThreatIndicator(kind, h, "AUTO_C2_HOST", UrlThreatClassification.MALWARE)
            phishCommunityIndex.contains(h) && sourceFresh(SOURCE_PHISH_COMMUNITY, now, PHISHING_TTL_MS) ->
                UrlThreatIndicator(kind, h, "AUTO_PHISHING_COMMUNITY", UrlThreatClassification.SUSPICIOUS_SOURCE)
            else -> null
        }
    }

    @Synchronized fun reload() {
        malwareIndex = FixedSha256Index.load(fileHashes)
        phishPrimaryIndex = FixedSha256Index.load(phishPrimary)
        phishCommunityIndex = FixedSha256Index.load(phishCommunity)
        c2Index = FixedSha256Index.load(c2Hosts)
        sourceLastSuccess = readSourceSuccesses()
    }

    fun info(): AutonomousIntelInfo {
        val state = readState()
        val now = System.currentTimeMillis()
        return AutonomousIntelInfo(
            lastSuccessfulUpdateEpochMs = state.optLong("lastSuccessfulUpdateEpochMs", 0L),
            malwareFileHashes = malwareIndex.count,
            phishingHosts = phishPrimaryIndex.count + phishCommunityIndex.count,
            c2Hosts = c2Index.count,
            latestAndroidSecurityPatch = state.optString("latestAndroidSecurityPatch", "").takeIf { it.isNotBlank() },
            androidCveCount = state.optInt("androidCveCount", 0),
            successfulSourcesLastRun = state.optInt("successfulSourcesLastRun", 0),
            freshSources = SOURCE_KEYS.count { sourceFresh(it, now, SOURCE_STATUS_FRESH_MS) },
            totalSources = SOURCE_KEYS.size
        )
    }

    fun readHashes(kind: IndexKind): Set<String> = indexFile(kind).takeIf(File::isFile)?.readLines()
        ?.asSequence()?.map(String::trim)?.filter { HASH.matches(it) }?.toCollection(linkedSetOf()) ?: emptySet()

    @Synchronized fun replaceHashes(kind: IndexKind, hashes: Collection<String>, minCount: Int = 1, shrinkFloor: Double? = null): Boolean {
        val clean = hashes.asSequence().mapNotNull(::normalizeSha).distinct().sorted().toList()
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

    @Synchronized fun mergeFileHashes(newHashes: Collection<String>, maxEntries: Int = 100_000): Boolean {
        val merged = linkedSetOf<String>()
        merged += readHashes(IndexKind.MALWARE_FILES)
        merged += newHashes.mapNotNull(::normalizeSha)
        val bounded = if (merged.size <= maxEntries) merged else merged.toList().takeLast(maxEntries).toSet()
        return replaceHashes(IndexKind.MALWARE_FILES, bounded, minCount = 1)
    }

    @Synchronized fun replaceAndroidCves(cves: Collection<String>): Boolean {
        val clean = cves.asSequence().map { it.trim().uppercase(Locale.ROOT) }
            .filter(CVE::matches).distinct().sorted().toList()
        val newText = if (clean.isEmpty()) "" else clean.joinToString(separator = "\n", postfix = "\n")
        if (androidCves.isFile && androidCves.readText() == newText) return false
        atomicWrite(androidCves, newText.toByteArray(Charsets.US_ASCII))
        return true
    }

    @Synchronized fun updateState(
        lastSuccess: Long,
        successfulSources: Int,
        successfulSourceKeys: Set<String>,
        latestPatch: String? = null,
        cveCount: Int? = null
    ) {
        val state = readState()
        state.put("lastSuccessfulUpdateEpochMs", lastSuccess)
        state.put("successfulSourcesLastRun", successfulSources)
        successfulSourceKeys.filter(SOURCE_KEYS::contains).forEach { key -> state.put("source_${key}_lastSuccessEpochMs", lastSuccess) }
        latestPatch?.let { current ->
            val old = state.optString("latestAndroidSecurityPatch", "")
            if (old.isBlank() || current >= old) state.put("latestAndroidSecurityPatch", current)
        }
        cveCount?.let { state.put("androidCveCount", it.coerceAtLeast(0)) }
        atomicWrite(stateFile, state.toString().toByteArray(Charsets.UTF_8))
        sourceLastSuccess = readSourceSuccesses()
    }

    private fun readSourceSuccesses(): Map<String, Long> {
        val state = readState()
        return SOURCE_KEYS.associateWith { key -> state.optLong("source_${key}_lastSuccessEpochMs", 0L) }
    }

    private fun sourceFresh(key: String, now: Long, ttlMs: Long): Boolean {
        val last = sourceLastSuccess[key] ?: 0L
        return last > 0L && now >= last && now - last <= ttlMs
    }

    enum class IndexKind { MALWARE_FILES, PHISHING_PRIMARY, PHISHING_COMMUNITY, C2_HOSTS }

    private fun indexFile(kind: IndexKind): File = when (kind) {
        IndexKind.MALWARE_FILES -> fileHashes
        IndexKind.PHISHING_PRIMARY -> phishPrimary
        IndexKind.PHISHING_COMMUNITY -> phishCommunity
        IndexKind.C2_HOSTS -> c2Hosts
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
        const val SOURCE_C2 = "c2"
        const val SOURCE_ANDROID_BULLETIN = "android_bulletin"
        private val SOURCE_KEYS = listOf(SOURCE_MALWARE, SOURCE_PHISH_PRIMARY, SOURCE_PHISH_COMMUNITY, SOURCE_C2, SOURCE_ANDROID_BULLETIN)
        private const val SOURCE_STATUS_FRESH_MS = 18L * 60L * 60L * 1000L
        private const val PHISHING_TTL_MS = 7L * 24L * 60L * 60L * 1000L
        private const val C2_TTL_MS = 36L * 60L * 60L * 1000L
        private val HASH = Regex("^[a-f0-9]{64}$")
        private val CVE = Regex("^CVE-20\\d{2}-\\d{4,8}$")
        fun sha256(text: String): String = MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
