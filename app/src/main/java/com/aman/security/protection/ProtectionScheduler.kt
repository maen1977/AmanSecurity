package com.aman.security.protection

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf
import java.util.concurrent.TimeUnit

object ProtectionScheduler {
    private const val PERIODIC_WORK_NAME = "aman_protected_folder_periodic"
    private const val IMMEDIATE_WORK_NAME = "aman_protected_folder_immediate"
    private const val APP_RESCAN_WORK_NAME = "aman_installed_apps_reputation_rescan"
    private const val APP_RESCAN_NOW_WORK_NAME = "aman_installed_apps_reputation_rescan_now"
    private const val DOWNLOAD_RESCAN_WORK_NAME = "aman_downloads_realtime_catchup"
    private const val DOWNLOAD_RESCAN_NOW_WORK_NAME = "aman_downloads_realtime_now"
    private const val CACHED_REPUTATION_SWEEP_WORK_NAME = "aman_cached_reputation_sweep_now"
    private const val INTRUSION_MONITOR_WORK_NAME = "aman_intrusion_monitor_6h"
    private const val INTRUSION_MONITOR_NOW_WORK_NAME = "aman_intrusion_monitor_now"

    fun enable(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiresBatteryNotLow(true)
            .setRequiresStorageNotLow(true)
            .build()
        val request = PeriodicWorkRequestBuilder<ProtectedFolderWorker>(6, TimeUnit.HOURS, 1, TimeUnit.HOURS)
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        val workManager = WorkManager.getInstance(context)
        workManager.enqueueUniquePeriodicWork(
            PERIODIC_WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            request
        )

        val appConstraints = Constraints.Builder()
            .setRequiresBatteryNotLow(true)
            .setRequiresStorageNotLow(true)
            .build()
        val appRescan = PeriodicWorkRequestBuilder<InstalledAppsRescanWorker>(24, TimeUnit.HOURS, 3, TimeUnit.HOURS)
            .setConstraints(appConstraints)
            .build()
        workManager.enqueueUniquePeriodicWork(
            APP_RESCAN_WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            appRescan
        )

        val downloadsRescan = PeriodicWorkRequestBuilder<DownloadProtectionWorker>(2, TimeUnit.HOURS, 30, TimeUnit.MINUTES)
            .setConstraints(
                Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .setRequiresStorageNotLow(true)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
            .build()
        workManager.enqueueUniquePeriodicWork(
            DOWNLOAD_RESCAN_WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            downloadsRescan
        )

        val intrusionMonitor = PeriodicWorkRequestBuilder<IntrusionMonitorWorker>(6, TimeUnit.HOURS, 1, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        workManager.enqueueUniquePeriodicWork(
            INTRUSION_MONITOR_WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            intrusionMonitor
        )
        intrusionCheckNow(context)
        checkNow(context)
        scanDownloadsNow(context)
    }

    fun disable(context: Context) {
        val workManager = WorkManager.getInstance(context)
        workManager.cancelUniqueWork(PERIODIC_WORK_NAME)
        workManager.cancelUniqueWork(IMMEDIATE_WORK_NAME)
        workManager.cancelUniqueWork(APP_RESCAN_WORK_NAME)
        workManager.cancelUniqueWork(APP_RESCAN_NOW_WORK_NAME)
        workManager.cancelUniqueWork(DOWNLOAD_RESCAN_WORK_NAME)
        workManager.cancelUniqueWork(DOWNLOAD_RESCAN_NOW_WORK_NAME)
        workManager.cancelUniqueWork(CACHED_REPUTATION_SWEEP_WORK_NAME)
        workManager.cancelUniqueWork(INTRUSION_MONITOR_WORK_NAME)
        workManager.cancelUniqueWork(INTRUSION_MONITOR_NOW_WORK_NAME)
        workManager.cancelAllWorkByTag(PACKAGE_SCAN_TAG)
        workManager.cancelAllWorkByTag(DOWNLOAD_SCAN_TAG)
    }

    fun checkNow(context: Context) {
        val request = OneTimeWorkRequestBuilder<ProtectedFolderWorker>()
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            IMMEDIATE_WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            request
        )
    }


    fun rescanInstalledAppsNow(context: Context) {
        val request = OneTimeWorkRequestBuilder<InstalledAppsRescanWorker>()
            .setConstraints(
                Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .setRequiresStorageNotLow(true)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            APP_RESCAN_NOW_WORK_NAME,
            ExistingWorkPolicy.KEEP,
            request
        )
    }


    fun scanDownloadsNow(context: Context) {
        val request = OneTimeWorkRequestBuilder<DownloadProtectionWorker>()
            .setConstraints(
                Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .setRequiresStorageNotLow(true)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
            .addTag(DOWNLOAD_SCAN_TAG)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            DOWNLOAD_RESCAN_NOW_WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    fun recheckCachedReputationNow(context: Context) {
        val request = OneTimeWorkRequestBuilder<CachedReputationSweepWorker>()
            .setConstraints(
                Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            CACHED_REPUTATION_SWEEP_WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    fun intrusionCheckNow(context: Context) {
        val request = OneTimeWorkRequestBuilder<IntrusionMonitorWorker>()
            .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            INTRUSION_MONITOR_NOW_WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    fun scanDownloadedFile(context: Context, absolutePath: String) {
        if (absolutePath.isBlank()) return
        val request = OneTimeWorkRequestBuilder<DownloadProtectionWorker>()
            .setInputData(workDataOf(DownloadProtectionWorker.KEY_FILE_PATH to absolutePath))
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 10, TimeUnit.MINUTES)
            .addTag(DOWNLOAD_SCAN_TAG)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            "aman_download_file_${absolutePath.hashCode()}",
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    fun scanNewPackage(context: Context, packageName: String) {
        val request = OneTimeWorkRequestBuilder<NewPackageScanWorker>()
            .setInputData(workDataOf(NewPackageScanWorker.KEY_PACKAGE_NAME to packageName))
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 10, TimeUnit.MINUTES)
            .addTag(PACKAGE_SCAN_TAG)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            "aman_package_scan_${packageName.hashCode()}",
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    private const val PACKAGE_SCAN_TAG = "aman_package_scan"
    private const val DOWNLOAD_SCAN_TAG = "aman_download_scan"
}
