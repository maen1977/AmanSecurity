package com.aman.security.protection

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.scanner.InstalledAppScanner
import com.aman.security.scanner.SignatureDatabase

class NewPackageScanWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : Worker(appContext, workerParams) {
    override fun doWork(): Result {
        val preferences = ProtectionPreferences(applicationContext)
        if (!preferences.enabled) return Result.success()
        val packageName = inputData.getString(KEY_PACKAGE_NAME)?.takeIf { it.isNotBlank() }
            ?: return Result.failure()
        if (packageName == applicationContext.packageName) return Result.success()

        return runCatching {
            val database = SignatureDatabase(applicationContext)
            val result = InstalledAppScanner(applicationContext, database).scanPackageByName(packageName)
                ?: return Result.success()
            if (!ProtectionPolicy.shouldNotifyApp(result.riskLevel)) {
                preferences.replaceAppFingerprint(packageName, AppRescanPolicy.fingerprint(result))
                return Result.success()
            }
            val fingerprint = AppRescanPolicy.fingerprint(result)
            val previous = preferences.replaceAppFingerprint(packageName, fingerprint)
            if (!AppRescanPolicy.shouldNotify(previous, result)) return Result.success()
            val severity = ProtectionPolicy.severityForApp(result.riskLevel) ?: return Result.success()
            val event = ProtectionEventStore(applicationContext).add(
                type = ProtectionEventType.APP,
                displayName = result.appName,
                detail = result.packageName,
                severity = severity
            )
            ProtectionNotifier.notifyEvent(applicationContext, event)
            Result.success()
        }.getOrElse { Result.retry() }
    }

    companion object {
        const val KEY_PACKAGE_NAME = "package_name"
    }
}
