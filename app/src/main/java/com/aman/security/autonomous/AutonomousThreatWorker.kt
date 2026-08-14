package com.aman.security.autonomous

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.ForegroundInfo
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.R
import com.aman.security.protection.ProtectionPreferences
import com.aman.security.protection.ProtectionScheduler
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.web.LocalWebShieldController

class AutonomousThreatWorker(appContext: Context, params: WorkerParameters) : Worker(appContext, params) {
    override fun getForegroundInfo(): ForegroundInfo {
        val manager = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    UPDATE_CHANNEL,
                    applicationContext.getString(R.string.protection_updates_title),
                    NotificationManager.IMPORTANCE_LOW
                ).apply { description = applicationContext.getString(R.string.threat_update_notification) }
            )
        }
        val notification = NotificationCompat.Builder(applicationContext, UPDATE_CHANNEL)
            .setSmallIcon(R.drawable.ic_shield_white)
            .setContentTitle(applicationContext.getString(R.string.protection_updates_title))
            .setContentText(applicationContext.getString(R.string.threat_update_notification))
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setProgress(0, 0, true)
            .build()
        return ForegroundInfo(UPDATE_NOTIFICATION_ID, notification)
    }

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
            is AutonomousUpdateResult.NoSourceAvailable -> Result.retry()
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

    private companion object {
        const val UPDATE_CHANNEL = "aman-threat-updates"
        const val UPDATE_NOTIFICATION_ID = 3505
    }
}
