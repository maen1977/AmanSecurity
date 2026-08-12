package com.aman.security.protection

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.io.File
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.R
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.InstalledAppScanner
import com.aman.security.scanner.SignatureDatabase

/**
 * Re-checks cached SHA-256 values against freshly downloaded local threat intelligence.
 * No APK/file is opened here, so the six-hour database refresh does not trigger a heavy
 * full-device rescan.
 */
class CachedReputationSweepWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : Worker(appContext, workerParams) {
    override fun doWork(): Result {
        val preferences = ProtectionPreferences(applicationContext)
        if (!preferences.enabled) return Result.success()

        return runCatching {
            val database = SignatureDatabase(applicationContext)
            val cache = LocalScanCacheStore(applicationContext)
            val events = ProtectionEventStore(applicationContext)
            val activity = ProtectionActivityStore(applicationContext)
            var checked = 0
            var alerts = 0
            val existingKeys = events.events().mapTo(linkedSetOf()) { event ->
                "${event.type}:${event.detail}:${event.severity}"
            }

            var cachedApps = cache.loadApps()
            if (cachedApps.isEmpty()) {
                // One-time local baseline. Later six-hour updates re-check hashes only.
                val baseline = InstalledAppScanner(applicationContext, database).scanUserApps(deep = false)
                preferences.totalAppsChecked += baseline.scannedApps.toLong()
                cachedApps = cache.loadApps()
            }
            cachedApps.values.forEach { app ->
                val threat = app.componentHashes.asSequence()
                    .onEach { checked++ }
                    .mapNotNull(database::find)
                    .firstOrNull { it.classification == ScanClassification.KNOWN_THREAT }
                    ?: return@forEach
                val eventKey = "${ProtectionEventType.APP}:${app.packageName}:${ProtectionSeverity.KNOWN_THREAT}"
                if (eventKey !in existingKeys) {
                    val event = events.add(
                        type = ProtectionEventType.APP,
                        displayName = app.appName,
                        detail = app.packageName,
                        severity = ProtectionSeverity.KNOWN_THREAT
                    )
                    ProtectionNotifier.notifyEvent(applicationContext, event)
                    preferences.totalThreatsDetected += 1L
                    existingKeys += eventKey
                    alerts++
                }
            }

            cache.loadFiles().values.forEach { file ->
                if (!cachedFileStillPresent(file)) return@forEach
                checked++
                val threat = database.find(file.sha256)
                    ?.takeIf { it.classification == ScanClassification.KNOWN_THREAT }
                    ?: return@forEach
                val eventKey = "${ProtectionEventType.FILE}:${file.location}:${ProtectionSeverity.KNOWN_THREAT}"
                if (eventKey !in existingKeys) {
                    val event = events.add(
                        type = ProtectionEventType.FILE,
                        displayName = file.displayName,
                        detail = file.location,
                        severity = ProtectionSeverity.KNOWN_THREAT
                    )
                    ProtectionNotifier.notifyEvent(applicationContext, event)
                    preferences.totalThreatsDetected += 1L
                    existingKeys += eventKey
                    alerts++
                }
            }

            preferences.lastCachedReputationSweepAt = System.currentTimeMillis()
            preferences.lastCachedReputationSweepCount = checked
            preferences.markActivity(applicationContext.getString(R.string.activity_cached_reputation_sweep, checked))
            activity.add(
                kind = ProtectionActivityKind.DATABASE_UPDATE,
                state = if (alerts > 0) ProtectionActivityState.THREAT else ProtectionActivityState.SAFE,
                title = applicationContext.getString(R.string.timeline_cached_reputation_sweep, checked),
                detail = applicationContext.getString(R.string.timeline_cached_reputation_sweep_detail, alerts),
                dedupeKey = "${ProtectionActivityKind.DATABASE_UPDATE}:${applicationContext.getString(R.string.timeline_cached_reputation_sweep, checked)}:${applicationContext.getString(R.string.timeline_cached_reputation_sweep_detail, alerts)}"
            )
            ProtectionServiceController.refresh(applicationContext)
            Result.success()
        }.getOrElse { Result.retry() }
    }

    private fun cachedFileStillPresent(entry: CachedFileArtifact): Boolean = when (entry.scope) {
        LocalScanCacheStore.SCOPE_DOWNLOADS -> File(entry.location).isFile
        LocalScanCacheStore.SCOPE_PROTECTED_FOLDER -> {
            val parts = entry.location.split('\n', limit = 2)
            if (parts.size != 2) {
                true // Compatibility with pre-3.0 cache entries.
            } else {
                runCatching {
                    val treeUri = Uri.parse(parts[0])
                    val documentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, parts[1])
                    applicationContext.contentResolver.query(
                        documentUri,
                        arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID),
                        null, null, null
                    )?.use { it.moveToFirst() } == true
                }.getOrDefault(false)
            }
        }
        else -> false
    }
}
