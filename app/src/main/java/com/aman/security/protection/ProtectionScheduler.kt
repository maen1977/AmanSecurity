package com.aman.security.protection

import android.content.Context
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

    fun enable(context: Context) {
        val request = PeriodicWorkRequestBuilder<ProtectedFolderWorker>(15, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            PERIODIC_WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            request
        )
        checkNow(context)
    }

    fun disable(context: Context) {
        val workManager = WorkManager.getInstance(context)
        workManager.cancelUniqueWork(PERIODIC_WORK_NAME)
        workManager.cancelUniqueWork(IMMEDIATE_WORK_NAME)
        workManager.cancelAllWorkByTag(PACKAGE_SCAN_TAG)
    }

    fun checkNow(context: Context) {
        val request = OneTimeWorkRequestBuilder<ProtectedFolderWorker>().build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            IMMEDIATE_WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    fun scanNewPackage(context: Context, packageName: String) {
        val request = OneTimeWorkRequestBuilder<NewPackageScanWorker>()
            .setInputData(workDataOf(NewPackageScanWorker.KEY_PACKAGE_NAME to packageName))
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .addTag(PACKAGE_SCAN_TAG)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            "aman_package_scan_${packageName.hashCode()}",
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    private const val PACKAGE_SCAN_TAG = "aman_package_scan"
}
