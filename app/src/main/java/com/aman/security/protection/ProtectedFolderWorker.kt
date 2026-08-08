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
            scanner.scan(treeUri)
            Result.success()
        }.getOrElse { Result.retry() }
    }
}
