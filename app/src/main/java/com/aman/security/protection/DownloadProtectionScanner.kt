package com.aman.security.protection

import android.content.Context
import android.os.Environment
import com.aman.security.scanner.ApkStaticAnalyzer
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.ScanDetectionReason
import com.aman.security.scanner.ScanResult
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.security.QuarantineManager
import com.aman.security.security.QuarantinePolicy
import com.aman.security.security.SecurityRecordStore
import java.io.File
import java.security.MessageDigest
import java.util.ArrayDeque

data class DownloadScanSummary(
    val scannedFiles: Int,
    val skippedUnchanged: Int,
    val alerts: Int,
    val knownThreats: Int,
    val highRisk: Int,
    val inaccessible: Int,
    val truncated: Boolean,
    val accessMissing: Boolean,
    val quarantinedFiles: Int = 0,
    val quarantineFailures: Int = 0
)

/**
 * Antivirus-oriented Downloads scanner. New/changed files are read and hashed locally.
 * Unchanged files reuse their cached SHA-256, so threat-database updates can re-check
 * reputation without re-reading storage or burning CPU/battery.
 */
class DownloadProtectionScanner(private val context: Context) {
    private val preferences = ProtectionPreferences(context)
    private val activityStore = ProtectionActivityStore(context)
    private val eventStore = ProtectionEventStore(context)
    private val recordStore = SecurityRecordStore(context)
    private val quarantineManager = QuarantineManager(context, recordStore)
    private val database = SignatureDatabase(context)
    private val scanner = FileScanner(
        context.contentResolver,
        database,
        ApkStaticAnalyzer(context, database)
    )
    private val cacheStore = LocalScanCacheStore(context)

    fun scanChangedFiles(
        specificFile: File? = null,
        onProgress: ((completed: Int, total: Int, currentName: String, currentPath: String) -> Unit)? = null
    ): DownloadScanSummary {
        if (!ProtectionAccess.hasDownloadsReadAccess(context)) {
            preferences.lastDownloadsScanAt = System.currentTimeMillis()
            return DownloadScanSummary(0, 0, 0, 0, 0, 0, false, true)
        }

        val fileCache = cacheStore.loadFiles()
        val candidates = if (specificFile != null) listOf(specificFile) else enumerateDownloads().toList()
        val totalCandidates = candidates.size.coerceAtLeast(1)

        var visited = 0
        var scanned = 0
        var skipped = 0
        var alerts = 0
        var known = 0
        var high = 0
        var inaccessible = 0
        var quarantinedFiles = 0
        var quarantineFailures = 0
        var truncated = false

        for ((candidateIndex, file) in candidates.withIndex()) {
            if (visited >= MAX_DOWNLOAD_DOCUMENTS || scanned >= MAX_DOWNLOAD_SCANS_PER_RUN) {
                truncated = true
                break
            }
            visited++
            if (!file.isFile || !file.canRead()) {
                inaccessible++
                continue
            }
            val size = runCatching { file.length() }.getOrDefault(-1L)
            if (!ProtectionPolicy.shouldScanFile(file.name, size)) continue

            val key = cacheKey(file.absolutePath)
            val metadataFingerprint = "$size:${runCatching { file.lastModified() }.getOrDefault(-1L)}"
            val cached = fileCache[key]?.takeIf {
                it.scope == LocalScanCacheStore.SCOPE_DOWNLOADS && it.metadataFingerprint == metadataFingerprint
            }
            if (cached != null) {
                skipped++
                val cachedThreat = database.find(cached.sha256)
                if (cachedThreat != null) {
                    val cachedResult = ScanResult(
                        fileName = file.name,
                        sizeBytes = size,
                        sha256 = cached.sha256,
                        classification = cachedThreat.classification,
                        signatureId = cachedThreat.id,
                        detectionReason = if (cachedThreat.classification == ScanClassification.TEST_SIGNATURE) {
                            ScanDetectionReason.TEST_SIGNATURE
                        } else {
                            ScanDetectionReason.KNOWN_FILE_SIGNATURE
                        }
                    )
                    val outcome = handleResult(cachedResult, file, fromCachedReputation = true)
                    alerts += outcome.alerts
                    known += outcome.known
                    high += outcome.high
                    quarantinedFiles += outcome.quarantined
                    quarantineFailures += outcome.quarantineFailures
                }
                continue
            }

            onProgress?.invoke(candidateIndex, totalCandidates, file.name, file.absolutePath)
            val outcome = runCatching { scanner.scan(file) }
            if (outcome.isFailure) {
                inaccessible++
                continue
            }
            val result = outcome.getOrThrow()
            scanned++
            preferences.totalFilesChecked += 1L
            preferences.markActivity(context.getString(com.aman.security.R.string.activity_download_checked, file.name))
            onProgress?.invoke(candidateIndex + 1, totalCandidates, file.name, file.absolutePath)

            fileCache[key] = CachedFileArtifact(
                key = key,
                scope = LocalScanCacheStore.SCOPE_DOWNLOADS,
                displayName = result.fileName,
                location = file.absolutePath,
                metadataFingerprint = metadataFingerprint,
                sha256 = result.sha256,
                lastSeenAt = System.currentTimeMillis()
            )

            val handled = handleResult(result, file, fromCachedReputation = false)
            alerts += handled.alerts
            known += handled.known
            high += handled.high
            quarantinedFiles += handled.quarantined
            quarantineFailures += handled.quarantineFailures
        }

        cacheStore.saveFiles(fileCache)
        preferences.lastDownloadsScanAt = System.currentTimeMillis()
        preferences.lastDownloadsScannedCount = scanned
        preferences.lastDownloadsAlertCount = alerts
        return DownloadScanSummary(
            scannedFiles = scanned,
            skippedUnchanged = skipped,
            alerts = alerts,
            knownThreats = known,
            highRisk = high,
            inaccessible = inaccessible,
            truncated = truncated,
            accessMissing = false,
            quarantinedFiles = quarantinedFiles,
            quarantineFailures = quarantineFailures
        )
    }

    private fun handleResult(result: ScanResult, file: File, fromCachedReputation: Boolean): ResultCounts {
        if (result.classification == ScanClassification.KNOWN_THREAT || result.classification == ScanClassification.SUSPICIOUS) {
            recordStore.recordScan(result)
        }

        val excluded = recordStore.isExcluded(result.sha256)
        val severity = if (ProtectionPolicy.shouldNotifyFile(result, excluded)) ProtectionPolicy.severityForFile(result) else null
        var quarantined = false
        var quarantineFailure = false
        if (QuarantinePolicy.shouldAutoQuarantine(result.classification, excluded)) {
            when (quarantineManager.quarantine(file, result)) {
                is QuarantineManager.QuarantineResult.Success -> {
                    quarantined = true
                    activityStore.add(
                        kind = ProtectionActivityKind.DOWNLOAD_SCAN,
                        state = ProtectionActivityState.THREAT,
                        title = context.getString(com.aman.security.R.string.activity_download_quarantined, result.fileName),
                        detail = result.sha256,
                        dedupeKey = "quarantined:${result.sha256}"
                    )
                }
                else -> quarantineFailure = true
            }
        }
        if (severity != null) {
            val alreadyPresent = eventStore.events().any {
                it.type == ProtectionEventType.FILE && it.detail == file.absolutePath && it.severity == severity
            }
            if (!alreadyPresent) {
                val event = eventStore.add(
                    type = ProtectionEventType.FILE,
                    displayName = result.fileName,
                    detail = file.absolutePath,
                    severity = severity
                )
                ProtectionNotifier.notifyEvent(context, event)
                preferences.totalThreatsDetected += 1L
                activityStore.add(
                    kind = ProtectionActivityKind.DOWNLOAD_SCAN,
                    state = ProtectionActivityState.THREAT,
                    title = context.getString(com.aman.security.R.string.timeline_download_threat, result.fileName),
                    detail = file.absolutePath
                )
                return ResultCounts(
                    alerts = 1,
                    known = if (severity == ProtectionSeverity.KNOWN_THREAT) 1 else 0,
                    high = if (severity == ProtectionSeverity.HIGH_RISK) 1 else 0,
                    quarantined = if (quarantined) 1 else 0,
                    quarantineFailures = if (quarantineFailure) 1 else 0
                )
            }
            return ResultCounts(
                quarantined = if (quarantined) 1 else 0,
                quarantineFailures = if (quarantineFailure) 1 else 0
            )
        }

        if (!fromCachedReputation) {
            val state = when {
                isInstallablePackage(file) -> ProtectionActivityState.ATTENTION
                result.classification == ScanClassification.SUSPICIOUS || result.classification == ScanClassification.UNKNOWN_APK -> ProtectionActivityState.ATTENTION
                else -> ProtectionActivityState.SAFE
            }
            if (isInstallablePackage(file)) {
                val detail = context.getString(
                    com.aman.security.R.string.timeline_download_untrusted_source_detail,
                    file.absolutePath
                )
                activityStore.add(
                    kind = ProtectionActivityKind.DOWNLOAD_SCAN,
                    state = ProtectionActivityState.ATTENTION,
                    title = context.getString(
                        com.aman.security.R.string.timeline_download_untrusted_source,
                        result.fileName
                    ),
                    detail = detail,
                    dedupeKey = "download-review:${result.sha256}"
                )
                ProtectionNotifier.notifyDownloadedPackageReview(
                    context,
                    result.fileName,
                    file.absolutePath,
                    result.sha256
                )
            } else {
                activityStore.add(
                    kind = ProtectionActivityKind.DOWNLOAD_SCAN,
                    state = state,
                    title = context.getString(com.aman.security.R.string.timeline_download_checked, result.fileName),
                    detail = file.parent ?: Environment.DIRECTORY_DOWNLOADS,
                    dedupeKey = "${ProtectionActivityKind.DOWNLOAD_SCAN}:${context.getString(com.aman.security.R.string.timeline_download_checked, result.fileName)}:${file.parent ?: Environment.DIRECTORY_DOWNLOADS}"
                )
            }
        }
        return ResultCounts()
    }

    private fun isInstallablePackage(file: File): Boolean {
        val name = file.name.lowercase()
        return name.endsWith(".apk") || name.endsWith(".apks") ||
            name.endsWith(".xapk") || name.endsWith(".apkm") || name.endsWith(".zip")
    }

    private fun enumerateDownloads(): Sequence<File> = sequence {
        @Suppress("DEPRECATION")
        val root = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!root.exists() || !root.canRead()) return@sequence
        val queue = ArrayDeque<Pair<File, Int>>()
        queue.add(root to 0)
        var seen = 0
        while (queue.isNotEmpty() && seen < MAX_DOWNLOAD_DOCUMENTS) {
            val (directory, depth) = queue.removeFirst()
            val children = runCatching { directory.listFiles()?.toList().orEmpty() }.getOrDefault(emptyList())
            for (child in children) {
                if (seen++ >= MAX_DOWNLOAD_DOCUMENTS) return@sequence
                if (child.isDirectory && depth < MAX_DOWNLOAD_DEPTH) queue.add(child to depth + 1)
                else if (child.isFile) yield(child)
            }
        }
    }

    private fun cacheKey(path: String): String = "downloads:" + MessageDigest.getInstance("SHA-256")
        .digest(path.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

    private data class ResultCounts(
        val alerts: Int = 0,
        val known: Int = 0,
        val high: Int = 0,
        val quarantined: Int = 0,
        val quarantineFailures: Int = 0
    )

    companion object {
        private const val MAX_DOWNLOAD_DOCUMENTS = 3000
        private const val MAX_DOWNLOAD_SCANS_PER_RUN = 120
        private const val MAX_DOWNLOAD_DEPTH = 8
    }
}
