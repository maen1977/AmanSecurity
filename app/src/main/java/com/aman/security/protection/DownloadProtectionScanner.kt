package com.aman.security.protection

import android.content.Context
import android.os.Environment
import com.aman.security.scanner.ApkStaticAnalyzer
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.SignatureDatabase
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
    val accessMissing: Boolean
)

/**
 * Antivirus-oriented Downloads scanner. It runs only after the user grants
 * Android's all-files access (or legacy read access on Android 10 and below).
 * Files are processed locally and a ledger prevents repeatedly hashing unchanged files.
 */
class DownloadProtectionScanner(private val context: Context) {
    private val preferences = ProtectionPreferences(context)
    private val activityStore = ProtectionActivityStore(context)
    private val eventStore = ProtectionEventStore(context)
    private val recordStore = SecurityRecordStore(context)
    private val database = SignatureDatabase(context)
    private val scanner = FileScanner(
        context.contentResolver,
        database,
        ApkStaticAnalyzer(context, database)
    )

    fun scanChangedFiles(
        specificFile: File? = null,
        onProgress: ((completed: Int, total: Int, currentName: String, currentPath: String) -> Unit)? = null
    ): DownloadScanSummary {
        if (!ProtectionAccess.hasDownloadsReadAccess(context)) {
            preferences.lastDownloadsScanAt = System.currentTimeMillis()
            return DownloadScanSummary(0, 0, 0, 0, 0, 0, false, true)
        }

        val ledger = preferences.downloadLedger()
        val candidates = if (specificFile != null) {
            listOf(specificFile)
        } else {
            enumerateDownloads().toList()
        }
        val totalCandidates = candidates.size.coerceAtLeast(1)

        var visited = 0
        var scanned = 0
        var skipped = 0
        var alerts = 0
        var known = 0
        var high = 0
        var inaccessible = 0
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

            val key = ledgerKey(file.absolutePath)
            val fingerprint = "$size:${file.lastModified()}"
            if (ledger[key] == fingerprint) {
                skipped++
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
            ledger[key] = fingerprint
            preferences.totalFilesChecked += 1L
            preferences.markActivity(context.getString(com.aman.security.R.string.activity_download_checked, file.name))
            onProgress?.invoke(candidateIndex + 1, totalCandidates, file.name, file.absolutePath)

            if (result.classification == ScanClassification.KNOWN_THREAT ||
                result.classification == ScanClassification.SUSPICIOUS
            ) {
                recordStore.recordScan(result)
            }

            val excluded = recordStore.isExcluded(result.sha256)
            val severity = if (ProtectionPolicy.shouldNotifyFile(result, excluded)) {
                ProtectionPolicy.severityForFile(result)
            } else null
            if (severity != null) {
                val event = eventStore.add(
                    type = ProtectionEventType.FILE,
                    displayName = result.fileName,
                    detail = file.absolutePath,
                    severity = severity
                )
                ProtectionNotifier.notifyEvent(context, event)
                preferences.totalThreatsDetected += 1L
                alerts++
                if (severity == ProtectionSeverity.KNOWN_THREAT) known++ else high++
                activityStore.add(
                    kind = ProtectionActivityKind.DOWNLOAD_SCAN,
                    state = ProtectionActivityState.THREAT,
                    title = context.getString(com.aman.security.R.string.timeline_download_threat, result.fileName),
                    detail = file.absolutePath
                )
            } else {
                val state = when (result.classification) {
                    ScanClassification.SUSPICIOUS, ScanClassification.UNKNOWN_APK -> ProtectionActivityState.ATTENTION
                    else -> ProtectionActivityState.SAFE
                }
                activityStore.add(
                    kind = ProtectionActivityKind.DOWNLOAD_SCAN,
                    state = state,
                    title = context.getString(com.aman.security.R.string.timeline_download_checked, result.fileName),
                    detail = file.parent ?: Environment.DIRECTORY_DOWNLOADS,
                    dedupeKey = "${ProtectionActivityKind.DOWNLOAD_SCAN}:${context.getString(com.aman.security.R.string.timeline_download_checked, result.fileName)}:${file.parent ?: Environment.DIRECTORY_DOWNLOADS}"
                )
            }
        }

        preferences.saveDownloadLedger(ledger)
        preferences.lastDownloadsScanAt = System.currentTimeMillis()
        preferences.lastDownloadsScannedCount = scanned
        preferences.lastDownloadsAlertCount = alerts
        return DownloadScanSummary(scanned, skipped, alerts, known, high, inaccessible, truncated, false)
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
                if (child.isDirectory && depth < MAX_DOWNLOAD_DEPTH) {
                    queue.add(child to depth + 1)
                } else if (child.isFile) {
                    yield(child)
                }
            }
        }
    }

    private fun ledgerKey(path: String): String = MessageDigest.getInstance("SHA-256")
        .digest(path.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

    companion object {
        private const val MAX_DOWNLOAD_DOCUMENTS = 3000
        private const val MAX_DOWNLOAD_SCANS_PER_RUN = 240
        private const val MAX_DOWNLOAD_DEPTH = 8
    }
}
