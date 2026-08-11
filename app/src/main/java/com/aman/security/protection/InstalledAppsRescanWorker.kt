package com.aman.security.protection

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.scanner.InstalledAppScanner
import com.aman.security.scanner.SignatureDatabase

/**
 * Lightweight recurring app re-evaluation. It intentionally skips deep DEX
 * analysis because deep analysis already runs on install/update and manual full
 * scans. This pass re-hashes installed APKs and rechecks signer/package/file
 * reputation against the newest local threat intelligence so newly published signatures
 * can protect apps that were already installed.
 */
class InstalledAppsRescanWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : Worker(appContext, workerParams) {
    override fun doWork(): Result {
        val preferences = ProtectionPreferences(applicationContext)
        if (!preferences.enabled || !preferences.periodicAppRescanEnabled) return Result.success()

        return runCatching {
            val database = SignatureDatabase(applicationContext)
            val summary = InstalledAppScanner(applicationContext, database).scanUserApps(deep = false)
            var alerts = 0
            val previousLedger = preferences.appLedger()
            val currentLedger = linkedMapOf<String, String>()
            val store = ProtectionEventStore(applicationContext)

            summary.results.forEach { app ->
                val fingerprint = AppRescanPolicy.fingerprint(app)
                currentLedger[app.packageName] = fingerprint
                val previous = previousLedger[app.packageName]
                if (!AppRescanPolicy.shouldNotify(previous, app)) return@forEach
                val severity = ProtectionPolicy.severityForApp(app.riskLevel) ?: return@forEach
                val event = store.add(
                    type = ProtectionEventType.APP,
                    displayName = app.appName,
                    detail = app.packageName,
                    severity = severity
                )
                ProtectionNotifier.notifyEvent(applicationContext, event)
                alerts++
            }

            preferences.saveAppLedger(currentLedger)
            preferences.lastAppRescanAt = System.currentTimeMillis()
            preferences.lastAppRescanCount = summary.scannedApps
            preferences.lastAppAlertCount = alerts
            preferences.totalAppsChecked += summary.scannedApps.toLong()
            preferences.markActivity(applicationContext.getString(com.aman.security.R.string.activity_apps_rescan_complete, summary.scannedApps))
            ProtectionActivityStore(applicationContext).add(
                kind = ProtectionActivityKind.APP_SCAN,
                state = if (alerts > 0) ProtectionActivityState.THREAT else ProtectionActivityState.SAFE,
                title = applicationContext.getString(com.aman.security.R.string.timeline_apps_rescan_complete, summary.scannedApps),
                detail = applicationContext.getString(com.aman.security.R.string.timeline_apps_rescan_detail, alerts)
            )
            if (alerts > 0) preferences.totalThreatsDetected += alerts.toLong()
            ProtectionServiceController.refresh(applicationContext)
            Result.success()
        }.getOrElse { Result.retry() }
    }
}
