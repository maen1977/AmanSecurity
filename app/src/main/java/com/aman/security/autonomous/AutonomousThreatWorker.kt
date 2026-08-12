package com.aman.security.autonomous

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.protection.ProtectionPreferences
import com.aman.security.protection.ProtectionScheduler
import com.aman.security.scanner.SignatureDatabase

class AutonomousThreatWorker(appContext: Context, params: WorkerParameters) : Worker(appContext, params) {
    override fun doWork(): Result {
        val database = SignatureDatabase(applicationContext)
        return when (AutonomousThreatUpdater(applicationContext, database).update()) {
            AutonomousUpdateResult.NoSourceAvailable -> Result.retry()
            is AutonomousUpdateResult.Success,
            is AutonomousUpdateResult.Partial -> {
                if (ProtectionPreferences(applicationContext).enabled) {
                    ProtectionScheduler.recheckCachedReputationNow(applicationContext)
                }
                Result.success()
            }
        }
    }
}
