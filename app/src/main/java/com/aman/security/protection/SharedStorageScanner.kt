package com.aman.security.protection

import android.content.Context
import android.os.Environment
import com.aman.security.scanner.ApkStaticAnalyzer
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.security.SecurityRecordStore
import java.io.File
import java.util.ArrayDeque

data class SharedStorageAlertFinding(
    val displayName: String,
    val location: String,
    val sha256: String,
    val severity: ProtectionSeverity
)

data class SharedStorageScanSummary(
    val scannedFiles: Int,
    val alerts: Int,
    val knownThreats: Int,
    val highRisk: Int,
    val inaccessible: Int,
    val candidates: Int,
    val truncated: Boolean,
    val accessMissing: Boolean,
    val findings: List<SharedStorageAlertFinding> = emptyList()
)

/** Manual full shared-storage scan used by the Scan Center. */
class SharedStorageScanner(private val context: Context) {
    private val preferences = ProtectionPreferences(context)
    private val database = SignatureDatabase(context)
    private val scanner = FileScanner(context.contentResolver, database, ApkStaticAnalyzer(context, database))
    private val events = ProtectionEventStore(context)
    private val records = SecurityRecordStore(context)
    private val timeline = ProtectionActivityStore(context)

    fun scan(
        cancelled: () -> Boolean = { false },
        onProgress: ((completed: Int, total: Int, currentName: String, currentPath: String) -> Unit)? = null
    ): SharedStorageScanSummary {
        if (!ProtectionAccess.hasDownloadsReadAccess(context)) {
            return SharedStorageScanSummary(0, 0, 0, 0, 0, 0, false, true)
        }
        val enumeration = enumerateCandidates(cancelled)
        val candidates = enumeration.first
        var scanned = 0
        var alerts = 0
        var known = 0
        var high = 0
        var inaccessible = 0
        val findings = mutableListOf<SharedStorageAlertFinding>()
        for ((index, file) in candidates.withIndex()) {
            if (cancelled()) break
            onProgress?.invoke(index, candidates.size, file.name, file.absolutePath)
            val outcome = runCatching { scanner.scan(file) }
            if (outcome.isFailure) {
                inaccessible++
                continue
            }
            val result = outcome.getOrThrow()
            scanned++
            preferences.totalFilesChecked += 1L
            if (result.classification == ScanClassification.KNOWN_THREAT || result.classification == ScanClassification.SUSPICIOUS) {
                records.recordScan(result)
            }
            val excluded = records.isExcluded(result.sha256)
            val severity = if (ProtectionPolicy.shouldNotifyFile(result, excluded)) ProtectionPolicy.severityForFile(result) else null
            if (severity != null) {
                val event = events.add(ProtectionEventType.FILE, result.fileName, file.absolutePath, severity)
                ProtectionNotifier.notifyEvent(context, event)
                preferences.totalThreatsDetected += 1L
                alerts++
                if (severity == ProtectionSeverity.KNOWN_THREAT) known++ else high++
                findings += SharedStorageAlertFinding(
                    displayName = result.fileName,
                    location = file.absolutePath,
                    sha256 = result.sha256,
                    severity = severity
                )
            }
            onProgress?.invoke(index + 1, candidates.size, file.name, file.absolutePath)
        }
        if (!cancelled()) {
            preferences.markActivity(context.getString(com.aman.security.R.string.activity_full_file_scan_complete, scanned))
            timeline.add(
                kind = ProtectionActivityKind.FILE_SCAN,
                state = if (alerts > 0) ProtectionActivityState.THREAT else ProtectionActivityState.SAFE,
                title = context.getString(com.aman.security.R.string.timeline_full_file_scan_complete, scanned),
                detail = context.getString(com.aman.security.R.string.timeline_full_file_scan_detail, alerts)
            )
            ProtectionServiceController.refresh(context)
        }
        return SharedStorageScanSummary(scanned, alerts, known, high, inaccessible, candidates.size, enumeration.second, false, findings)
    }

    private fun enumerateCandidates(cancelled: () -> Boolean): Pair<List<File>, Boolean> {
        @Suppress("DEPRECATION")
        val root = Environment.getExternalStorageDirectory()
        val queue = ArrayDeque<Pair<File, Int>>()
        val results = ArrayList<File>(1024)
        queue.add(root to 0)
        var visited = 0
        var truncated = false
        while (queue.isNotEmpty() && !cancelled()) {
            val (dir, depth) = queue.removeFirst()
            val children = runCatching { dir.listFiles()?.toList().orEmpty() }.getOrDefault(emptyList())
            for (child in children) {
                if (cancelled()) break
                if (++visited > MAX_VISITED) {
                    truncated = true
                    return results to truncated
                }
                if (child.isDirectory) {
                    if (depth < MAX_DEPTH && !isExcludedDirectory(child)) queue.add(child to depth + 1)
                    continue
                }
                if (!child.isFile || !child.canRead()) continue
                if (!ProtectionPolicy.shouldScanFile(child.name, runCatching { child.length() }.getOrDefault(-1L))) continue
                results += child
                if (results.size >= MAX_SCAN_FILES) {
                    truncated = true
                    return results to truncated
                }
            }
        }
        return results to truncated
    }

    private fun isExcludedDirectory(file: File): Boolean {
        val normalized = file.absolutePath.replace('\\', '/').lowercase()
        return normalized.endsWith("/android/data") || normalized.endsWith("/android/obb")
    }

    companion object {
        private const val MAX_VISITED = 50_000
        private const val MAX_SCAN_FILES = 5_000
        private const val MAX_DEPTH = 20
    }
}
