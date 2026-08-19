package com.aman.security.autonomous

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OutOfQuotaPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.random.Random

object AutonomousThreatScheduler {
    private const val PERIODIC_WORK = "aman-cloud-threat-intelligence-24h"
    private const val LEGACY_PERIODIC_WORK = "aman-cloud-threat-intelligence-12h"
    private const val ON_DEMAND_WORK = "aman-autonomous-threat-intelligence-now"

    private fun periodicNetworkConstraints(): Constraints = Constraints.Builder()
        // The signed bundle is small and the user explicitly expects a daily update even
        // when the device is using mobile data. WorkManager still waits for a connected network.
        // Do not wake a device that is critically low on power or storage for maintenance work.
        .setRequiredNetworkType(NetworkType.CONNECTED)
        .setRequiresBatteryNotLow(true)
        .setRequiresStorageNotLow(true)
        .build()

    private fun manualNetworkConstraints(): Constraints = Constraints.Builder()
        .setRequiredNetworkType(NetworkType.CONNECTED)
        .build()

    fun schedule(context: Context) {
        val app = context.applicationContext
        val network = periodicNetworkConstraints()
        val periodic = PeriodicWorkRequestBuilder<AutonomousThreatWorker>(24, TimeUnit.HOURS, 120, TimeUnit.MINUTES)
            .setConstraints(network)
            // Spread first-run checks across a four-hour window so a large install base does not
            // contact the public mirror at the same minute.
            .setInitialDelay(Random.nextLong(0L, TimeUnit.HOURS.toMinutes(4L) + 1L), TimeUnit.MINUTES)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        val workManager = WorkManager.getInstance(app)
        workManager.cancelUniqueWork(LEGACY_PERIODIC_WORK)
        workManager.enqueueUniquePeriodicWork(PERIODIC_WORK, ExistingPeriodicWorkPolicy.KEEP, periodic)

        val last = AutonomousThreatStore(app).info().lastSuccessfulUpdateEpochMs
        if (last == 0L || System.currentTimeMillis() - last >= TimeUnit.HOURS.toMillis(24)) {
            val state = ThreatUpdateStateStore(app)
            val snapshot = state.snapshot()
            // A queued manual request may run over mobile data. Never replace it from the
            // Wi-Fi-only bootstrap path, even when it becomes stale; the UI will expose retry.
            if (!snapshot.isActive) {
                state.queued()
                val initial = OneTimeWorkRequestBuilder<AutonomousThreatWorker>()
                    .setConstraints(network)
                    .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 20, TimeUnit.MINUTES)
                    .build()
                WorkManager.getInstance(app).enqueueUniqueWork(ON_DEMAND_WORK, ExistingWorkPolicy.KEEP, initial)
            }
        }
    }

    /** Manual update survives leaving MainActivity because WorkManager owns the operation. */
    fun updateNow(context: Context): UUID {
        val app = context.applicationContext
        ThreatUpdateStateStore(app).queued()
        val request = OneTimeWorkRequestBuilder<AutonomousThreatWorker>()
            .setConstraints(manualNetworkConstraints())
            // Manual updates are user-visible and must start promptly. If expedited quota is
            // unavailable, preserve correctness by falling back to a normal request.
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 20, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(app).enqueueUniqueWork(ON_DEMAND_WORK, ExistingWorkPolicy.REPLACE, request)
        return request.id
    }
}
