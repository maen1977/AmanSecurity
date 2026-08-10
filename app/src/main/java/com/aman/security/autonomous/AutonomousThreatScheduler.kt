package com.aman.security.autonomous

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

object AutonomousThreatScheduler {
    private const val PERIODIC_WORK = "aman-autonomous-threat-intelligence-6h"
    private const val ON_DEMAND_WORK = "aman-autonomous-threat-intelligence-now"

    fun schedule(context: Context) {
        val network = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
        val periodic = PeriodicWorkRequestBuilder<AutonomousThreatWorker>(6, TimeUnit.HOURS, 30, TimeUnit.MINUTES)
            .setConstraints(network)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(PERIODIC_WORK, ExistingPeriodicWorkPolicy.UPDATE, periodic)

        val last = AutonomousThreatStore(context).info().lastSuccessfulUpdateEpochMs
        if (last == 0L || System.currentTimeMillis() - last >= TimeUnit.HOURS.toMillis(6)) {
            val initial = OneTimeWorkRequestBuilder<AutonomousThreatWorker>().setConstraints(network).build()
            WorkManager.getInstance(context).enqueueUniqueWork(ON_DEMAND_WORK, ExistingWorkPolicy.KEEP, initial)
        }
    }
}
