package com.aman.security.autonomous

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.protection.ProtectionPreferences
import com.aman.security.protection.ProtectionScheduler
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.web.LocalWebShieldController

class AutonomousThreatWorker(appContext: Context, params: WorkerParameters) : Worker(appContext, params) {
    override fun doWork(): Result {
        val state = ThreatUpdateStateStore(applicationContext)
        state.running()
        val database = SignatureDatabase(applicationContext)
        val outcome = runCatching {
            AutonomousThreatUpdater(applicationContext, database).update { progress ->
                state.progress(progress)
            }
        }
        val result = outcome.getOrElse {
            state.fail(it.message ?: it.javaClass.simpleName)
            return Result.retry()
        }
        state.complete(result)
        return when (result) {
            AutonomousUpdateResult.NoSourceAvailable -> Result.retry()
            is AutonomousUpdateResult.Success,
            is AutonomousUpdateResult.Partial -> {
                if (ProtectionPreferences(applicationContext).enabled) {
                    // Recheck cached hashes only. Do not rescan the whole device after every DB update.
                    ProtectionScheduler.recheckCachedReputationNow(applicationContext)
                    LocalWebShieldController.refresh(applicationContext)
                }
                Result.success()
            }
        }
    }
}
