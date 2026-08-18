package com.aman.security.protection

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.io.File

class DownloadProtectionWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : Worker(appContext, workerParams) {
    override fun doWork(): Result {
        val prefs = ProtectionPreferences(applicationContext)
        if (!prefs.enabled || !prefs.downloadsProtectionEnabled) return Result.success()
        if (!ProtectionAccess.hasDownloadsReadAccess(applicationContext)) return Result.success()
        // Full scan owns the storage traversal; do not run a competing Downloads worker.
        val scan = ScanSessionStore(applicationContext).snapshot()
        if (scan.isActive && scan.mode == PersistentScanMode.FULL) return Result.success()

        val specificPath = inputData.getString(KEY_FILE_PATH)?.takeIf { it.isNotBlank() }
        return runCatching {
            DownloadProtectionScanner(applicationContext).scanChangedFiles(specificPath?.let(::File))
            ProtectionServiceController.refresh(applicationContext)
            Result.success()
        }.getOrElse { Result.retry() }
    }

    companion object {
        const val KEY_FILE_PATH = "file_path"
    }
}
