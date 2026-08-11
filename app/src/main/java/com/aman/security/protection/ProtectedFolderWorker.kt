package com.aman.security.protection

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.scanner.ApkStaticAnalyzer
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.security.SecurityRecordStore

class ProtectedFolderWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : Worker(appContext, workerParams) {
    override fun doWork(): Result {
        val preferences = ProtectionPreferences(applicationContext)
        if (!preferences.enabled) return Result.success()
        val treeUri = preferences.protectedTreeUri ?: return Result.success()

        return runCatching {
            val database = SignatureDatabase(applicationContext)
            val analyzer = ApkStaticAnalyzer(applicationContext, database)
            val fileScanner = FileScanner(applicationContext.contentResolver, database, analyzer)
            val eventStore = ProtectionEventStore(applicationContext)
            val recordStore = SecurityRecordStore(applicationContext)
            val scanner = ProtectedFolderScanner(
                resolver = applicationContext.contentResolver,
                fileScanner = fileScanner,
                preferences = preferences,
                eventStore = eventStore,
                recordStore = recordStore,
                notifier = { ProtectionNotifier.notifyEvent(applicationContext, it) }
            )
            val summary = scanner.scan(treeUri)
            preferences.totalFilesChecked += summary.scannedFiles.toLong()
            if (summary.alerts > 0) preferences.totalThreatsDetected += summary.alerts.toLong()
            preferences.markActivity(applicationContext.getString(com.aman.security.R.string.activity_folder_scan_complete, summary.scannedFiles))
            ProtectionActivityStore(applicationContext).add(
                kind = ProtectionActivityKind.FILE_SCAN,
                state = if (summary.alerts > 0) ProtectionActivityState.THREAT else ProtectionActivityState.SAFE,
                title = applicationContext.getString(com.aman.security.R.string.timeline_folder_scan_complete, summary.scannedFiles),
                detail = applicationContext.getString(com.aman.security.R.string.timeline_folder_scan_detail, summary.alerts)
            )
            ProtectionServiceController.refresh(applicationContext)
            Result.success()
        }.getOrElse { Result.retry() }
    }
}
