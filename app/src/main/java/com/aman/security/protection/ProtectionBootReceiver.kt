package com.aman.security.protection

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.aman.security.autonomous.AutonomousThreatScheduler
import com.aman.security.web.LocalWebShieldController

/** Restores opted-in protection after boot or an in-place app update. */
class ProtectionBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_LOCKED_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) return
        val appContext = context.applicationContext
        AutonomousThreatScheduler.schedule(appContext)
        val prefs = ProtectionPreferences(appContext)
        ProtectionServiceController.recoverPendingScan(appContext)
        if (!prefs.enabled) return
        ProtectionScheduler.enable(appContext)
        runCatching { ProtectionServiceController.start(appContext) }
        if (prefs.localWebShieldEnabled && LocalWebShieldController.isPermissionGranted(context)) {
            runCatching { LocalWebShieldController.start(appContext) }
        }
    }
}
