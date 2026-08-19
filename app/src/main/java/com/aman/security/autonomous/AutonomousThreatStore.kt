package com.aman.security.autonomous

import android.content.Context
import com.aman.security.detection.DetectionRuleset
import com.aman.security.detection.ReputationIndicator
import com.aman.security.detection.ReputationKind
import com.aman.security.scanner.ApkIdentityIndicator
import com.aman.security.scanner.ApkIndicatorKind
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.ThreatDbValidator
import com.aman.security.scanner.ThreatSignature
import com.aman.security.scanner.UrlIndicatorKind
import com.aman.security.scanner.UrlThreatClassification
import com.aman.security.scanner.UrlThreatIndicator
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Compact cloud-intelligence store.
 *
 * SHA-256 indexes are sorted fixed-width files and are memory-mapped for binary search. This keeps
 * large databases out of the managed Java heap on low-memory phones and avoids parsing feeds into
 * Strings/HashSets during updates or startup.
 */
class AutonomousThreatStore(context: Context) {
    private val root = File(context.filesDir, "cloud-intel-v1").apply { mkdirs() }
    private val currentDirectory = File(root, "current")
    private val stateFile = File(root, "state.json")

    private fun currentFile(name: String): File = File(currentDirectory, name)

    @Volatile private var malwareIndex = FixedSha256Index.load(currentFile(FILE_MALWARE))
    @Volatile private var phishPrimaryIndex = FixedSha256Index.load(currentFile(FILE_PHISH_PRIMARY))
    @Volatile private var phishOpenPhishIndex = FixedSha256Index.load(currentFile(FILE_PHISH_OPENPHISH))
    @Volatile private var phishCommunityIndex = FixedSha256Index.load(currentFile(FILE_PHISH_COMMUNITY))
    @Volatile private var malwareUrlIndex = FixedSha256Index.load(currentFile(FILE_MALWARE_URLS))
    @Volatile private var c2Index = FixedSha256Index.load(currentFile(FILE_C2))
    @Volatile private var apkIdentityIndicators = loadApkIndicators(currentFile(FILE_APK_IDENTITIES))
    @Volatile private var cloudDetectionRuleset = loadDetectionRules(currentFile(FILE_DETECTION_RULES))

    fun findFile(sha256: String): ThreatSignature? {
        val h = normalizeSha(sha256) ?: return null
        // Immutable file hashes remain useful even when the cloud package becomes stale.
        return if (malwareIndex.contains(h)) {
            ThreatSignature(h, "CLOUD_MALWARE_HASH", ScanClassification.KNOWN_THREAT)
        } else null
    }

    fun findUrl(kind: UrlIndicatorKind, sha256: String): UrlThreatIndicator? {
        val h = normalizeSha(sha256) ?: return null
        val age = packageAgeMs() ?: return null
        return when {
            phishOpenPhishIndex.contains(h) && age <= AutonomousFeedPolicy.phishingOpenPhishTtlMs ->
                UrlThreatIndicator(kind, h, "CLOUD_OPENPHISH", UrlThreatClassification.PHISHING)
            phishPrimaryIndex.contains(h) && age <= AutonomousFeedPolicy.phishingPrimaryTtlMs ->
                UrlThreatIndicator(kind, h, "CLOUD_PHISHING_PRIMARY", UrlThreatClassification.PHISHING)
            malwareUrlIndex.contains(h) && age <= AutonomousFeedPolicy.malwareUrlsTtlMs ->
                UrlThreatIndicator(kind, h, "CLOUD_MALWARE_URL", UrlThreatClassification.MALWARE)
            kind == UrlIndicatorKind.C2_HOST && c2Index.contains(h) && age <= AutonomousFeedPolicy.c2TtlMs ->
                UrlThreatIndicator(kind, h, "CLOUD_C2_HOST", UrlThreatClassification.C2_SERVER)
            phishCommunityIndex.contains(h) && age <= AutonomousFeedPolicy.phishingCommunityTtlMs ->
                UrlThreatIndicator(kind, h, "CLOUD_PHISHING_COMMUNITY", UrlThreatClassification.SUSPICIOUS_SOURCE)
            else -> null
        }
    }

    fun findApk(kind: ApkIndicatorKind, sha256: String): ApkIdentityIndicator? {
        val h = normalizeSha(sha256) ?: return null
        return apkIdentityIndicators["$kind:$h"]
    }

    fun findReputation(kind: ReputationKind, sha256: String): ReputationIndicator? {
        val h = normalizeSha(sha256) ?: return null
        return cloudDetectionRuleset.findReputation(kind, h)
    }

    @Synchronized fun createStagingDirectory(): File {
        val staging = File(root, "staging")
        staging.deleteRecursively()
        check(staging.mkdirs())
        return staging
    }

    /** Atomically swaps a fully verified staging directory into service. */
    @Synchronized fun installVerifiedPackage(
        staging: File,
        manifestBytes: ByteArray,
        manifest: CloudThreatManifest,
        completedAt: Long
    ): Boolean {
        require(staging.parentFile?.canonicalFile == root.canonicalFile)
        require(CloudThreatManifest.REQUIRED_FILES.all { File(staging, it).isFile })
        File(staging, "manifest.json").writeBytes(manifestBytes)

        val state = readState()
        val previousSerial = state.optLong("cloudSerial", 0L)
        if (manifest.serial < previousSerial) throw IllegalArgumentException("Threat database rollback rejected")
        if (manifest.serial == previousSerial && currentDirectory.isDirectory) {
            staging.deleteRecursively()
            recordCloudCheckSuccess(manifest, completedAt, changed = false)
            return false
        }

        val backup = File(root, "previous")
        backup.deleteRecursively()
        val hadCurrent = currentDirectory.isDirectory
        if (hadCurrent && !currentDirectory.renameTo(backup)) throw java.io.IOException("Could not stage current cloud intelligence")
        if (!staging.renameTo(currentDirectory)) {
            if (hadCurrent) backup.renameTo(currentDirectory)
            throw java.io.IOException("Could not activate cloud intelligence")
        }
        backup.deleteRecursively()
        recordCloudCheckSuccess(manifest, completedAt, changed = true)
        reload()
        return true
    }

    @Synchronized fun recordCloudUnchanged(manifest: CloudThreatManifest, checkedAt: Long) {
        val state = readState()
        val installedSerial = state.optLong("cloudSerial", 0L)
        if (installedSerial == manifest.serial && currentDirectory.isDirectory) {
            recordCloudCheckSuccess(manifest, checkedAt, changed = false)
        }
    }

    @Synchronized fun recordCloudFailure(attemptAt: Long) {
        val state = readState()
        state.put("lastAttemptEpochMs", attemptAt)
        state.put("successfulSourcesLastRun", 0)
        state.put("failedSourcesLastRun", 1)
        state.put("cloudConsecutiveFailures", (state.optInt("cloudConsecutiveFailures", 0) + 1).coerceAtMost(999))
        atomicWrite(stateFile, state.toString().toByteArray(Charsets.UTF_8))
    }

    private fun recordCloudCheckSuccess(manifest: CloudThreatManifest, at: Long, changed: Boolean) {
        val state = readState()
        state.put("lastAttemptEpochMs", at)
        state.put("lastSuccessfulUpdateEpochMs", at)
        state.put("successfulSourcesLastRun", 1)
        state.put("failedSourcesLastRun", 0)
        state.put("cloudConsecutiveFailures", 0)
        state.put("cloudLastSuccessEpochMs", at)
        state.put("cloudSerial", manifest.serial)
        state.put("cloudVersion", manifest.version)
        state.put("cloudGeneratedAt", manifest.generatedAt)
        state.put("cloudGeneratedAtEpochMs", manifest.generatedAtEpochMs)
        state.put("latestAndroidSecurityPatch", manifest.latestAndroidSecurityPatch ?: "")
        state.put("androidCveCount", manifest.files.getValue(FILE_ANDROID_CVES).entries)
        state.put("apkIdentityCount", manifest.files.getValue(FILE_APK_IDENTITIES).entries)
        state.put("detectionRuleCount", manifest.files.getValue(FILE_DETECTION_RULES).entries)
        val upstream = manifest.sources
        state.put("upstreamSourceCount", upstream.size)
        state.put("upstreamSourceFailures", upstream.count { !it.ok })
        state.put("upstreamSourceSkipped", upstream.count { it.detail.startsWith("skipped:", ignoreCase = true) })
        state.put("lastRunChanged", if (changed) 1 else 0)
        atomicWrite(stateFile, state.toString().toByteArray(Charsets.UTF_8))
    }

    @Synchronized fun reload() {
        malwareIndex = FixedSha256Index.load(currentFile(FILE_MALWARE))
        phishPrimaryIndex = FixedSha256Index.load(currentFile(FILE_PHISH_PRIMARY))
        phishOpenPhishIndex = FixedSha256Index.load(currentFile(FILE_PHISH_OPENPHISH))
        phishCommunityIndex = FixedSha256Index.load(currentFile(FILE_PHISH_COMMUNITY))
        malwareUrlIndex = FixedSha256Index.load(currentFile(FILE_MALWARE_URLS))
        c2Index = FixedSha256Index.load(currentFile(FILE_C2))
        apkIdentityIndicators = loadApkIndicators(currentFile(FILE_APK_IDENTITIES))
        cloudDetectionRuleset = loadDetectionRules(currentFile(FILE_DETECTION_RULES))
    }

    fun info(): AutonomousIntelInfo {
        val state = readState()
        val now = System.currentTimeMillis()
        val generated = state.optLong("cloudGeneratedAtEpochMs", 0L)
        val lastSuccess = state.optLong("cloudLastSuccessEpochMs", 0L)
        val ageMs = if (generated > 0L && now >= generated) now - generated else Long.MAX_VALUE
        val fresh = generated > 0L && ageMs <= AutonomousFeedPolicy.cloudBundle.statusFreshMs
        val health = listOf(
            AutonomousSourceHealth(
                key = SOURCE_CLOUD_BUNDLE,
                trust = AutonomousFeedTrust.PRIMARY,
                lastSuccessEpochMs = lastSuccess,
                ageHours = if (generated > 0L && now >= generated) TimeUnit.MILLISECONDS.toHours(ageMs) else null,
                fresh = fresh,
                itemCount = malwareIndex.count + phishPrimaryIndex.count + phishOpenPhishIndex.count +
                    phishCommunityIndex.count + malwareUrlIndex.count + c2Index.count + state.optInt("androidCveCount", 0) +
                    state.optInt("apkIdentityCount", 0) + state.optInt("detectionRuleCount", 0),
                consecutiveFailures = state.optInt("cloudConsecutiveFailures", 0)
            )
        )
        return AutonomousIntelInfo(
            lastSuccessfulUpdateEpochMs = state.optLong("lastSuccessfulUpdateEpochMs", 0L),
            lastAttemptEpochMs = state.optLong("lastAttemptEpochMs", 0L),
            malwareFileHashes = malwareIndex.count,
            phishingPrimaryHosts = phishPrimaryIndex.count,
            phishingOpenPhishHosts = phishOpenPhishIndex.count,
            phishingCommunityHosts = phishCommunityIndex.count,
            phishingHosts = phishPrimaryIndex.count + phishOpenPhishIndex.count + phishCommunityIndex.count,
            malwareUrlHosts = malwareUrlIndex.count,
            c2Hosts = c2Index.count,
            latestAndroidSecurityPatch = state.optString("latestAndroidSecurityPatch", "").takeIf { it.isNotBlank() },
            androidCveCount = state.optInt("androidCveCount", 0),
            apkIdentityEntries = state.optInt("apkIdentityCount", apkIdentityIndicators.size),
            detectionRuleEntries = state.optInt("detectionRuleCount", 0),
            successfulSourcesLastRun = state.optInt("successfulSourcesLastRun", 0),
            failedSourcesLastRun = state.optInt("failedSourcesLastRun", 0),
            upstreamSourceCount = state.optInt("upstreamSourceCount", 0),
            upstreamSourceFailures = state.optInt("upstreamSourceFailures", 0),
            upstreamSourceSkipped = state.optInt("upstreamSourceSkipped", 0),
            freshSources = health.count { it.fresh },
            staleSources = health.count { !it.fresh },
            totalSources = 1,
            sourceHealth = health,
            cloudSerial = state.optLong("cloudSerial", 0L),
            cloudVersion = state.optString("cloudVersion", "").takeIf(String::isNotBlank),
            cloudGeneratedAt = state.optString("cloudGeneratedAt", "").takeIf(String::isNotBlank),
            cloudGeneratedAtEpochMs = generated,
            cloudPackageFresh = fresh,
            cloudConsecutiveFailures = state.optInt("cloudConsecutiveFailures", 0)
        )
    }

    fun installedSerial(): Long = readState().optLong("cloudSerial", 0L)
    fun installedVersion(): String? = readState().optString("cloudVersion", "").takeIf(String::isNotBlank)

    private fun loadApkIndicators(file: File): Map<String, ApkIdentityIndicator> {
        if (!file.isFile || file.length() == 0L || file.length() > 8L * 1024L * 1024L) return emptyMap()
        return runCatching {
            file.bufferedReader(Charsets.US_ASCII, 16 * 1024).useLines { lines ->
                lines.asSequence()
                    .map(String::trim)
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .mapNotNull(ThreatDbValidator::parseApkIdentityLine)
                    .associateBy { "${it.kind}:${it.sha256}" }
            }
        }.getOrDefault(emptyMap())
    }

    private fun loadDetectionRules(file: File): DetectionRuleset {
        if (!file.isFile || file.length() == 0L || file.length() > 16L * 1024L * 1024L) return DetectionRuleset()
        return runCatching {
            val bytes = file.readBytes()
            val rows = bytes.toString(Charsets.UTF_8).lineSequence()
                .count { it.isNotBlank() && !it.trimStart().startsWith("#") }
            ThreatDbValidator.parseDetectionRules(bytes, rows)
        }.getOrDefault(DetectionRuleset())
    }

    private fun packageAgeMs(): Long? {
        val generated = readState().optLong("cloudGeneratedAtEpochMs", 0L)
        val now = System.currentTimeMillis()
        if (generated <= 0L || now < generated) return null
        return now - generated
    }

    private fun readState(): JSONObject = runCatching {
        if (stateFile.isFile) JSONObject(stateFile.readText()) else JSONObject()
    }.getOrElse { JSONObject() }

    private fun atomicWrite(target: File, bytes: ByteArray) {
        val temp = File(root, target.name + ".tmp")
        temp.outputStream().use { output ->
            output.write(bytes)
            runCatching { output.fd.sync() }
        }
        if (!temp.renameTo(target)) {
            target.delete()
            check(temp.renameTo(target))
        }
    }

    private fun normalizeSha(value: String): String? = value.trim().lowercase(Locale.ROOT).takeIf(HASH::matches)

    private class FixedSha256Index private constructor(
        private val mapped: MappedByteBuffer?,
        val count: Int
    ) {
        fun contains(hex: String): Boolean {
            if (mapped == null || !HASH.matches(hex)) return false
            var low = 0
            var high = count - 1
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
            val buffer = requireNotNull(mapped)
            for (i in 0 until 64) {
                val a = buffer.get(offset + i).toInt() and 0xff
                val b = hex[i].code
                if (a != b) return a - b
            }
            return 0
        }

        companion object {
            fun load(file: File): FixedSha256Index {
                if (!file.isFile || file.length() == 0L || file.length() % 65L != 0L) return FixedSha256Index(null, 0)
                val length = file.length()
                if (length > Int.MAX_VALUE) return FixedSha256Index(null, 0)
                val mapped = runCatching {
                    RandomAccessFile(file, "r").use { raf ->
                        raf.channel.map(FileChannel.MapMode.READ_ONLY, 0L, length)
                    }
                }.getOrNull() ?: return FixedSha256Index(null, 0)
                val count = (length / 65L).toInt()
                // Structural validation is constant-memory and happens once per mapped version.
                for (i in 0 until count) {
                    if (mapped.get(i * 65 + 64) != '\n'.code.toByte()) return FixedSha256Index(null, 0)
                }
                return FixedSha256Index(mapped, count)
            }
        }
    }

    companion object {
        const val SOURCE_CLOUD_BUNDLE = "cloud_bundle"
        const val FILE_MALWARE = "malware_files.sha256"
        const val FILE_PHISH_PRIMARY = "phishing_primary.sha256"
        const val FILE_PHISH_OPENPHISH = "phishing_openphish.sha256"
        const val FILE_PHISH_COMMUNITY = "phishing_community.sha256"
        const val FILE_MALWARE_URLS = "malware_url_hosts.sha256"
        const val FILE_C2 = "c2_hosts.sha256"
        const val FILE_ANDROID_CVES = "android_cves.txt"
        const val FILE_APK_IDENTITIES = "apk_indicators.csv"
        const val FILE_DETECTION_RULES = "detection_rules.csv"
        private val HASH = Regex("^[a-f0-9]{64}$")
        fun sha256(text: String): String = MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
