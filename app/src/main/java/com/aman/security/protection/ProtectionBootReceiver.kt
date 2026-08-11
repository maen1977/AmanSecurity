package com.aman.security.protection

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restores opted-in protection after boot or an in-place app update. */
class ProtectionBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_LOCKED_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) return
        val prefs = ProtectionPreferences(context)
        if (!prefs.enabled) return
        ProtectionScheduler.enable(context.applicationContext)
        runCatching { ProtectionServiceController.start(context.applicationContext) }
    }
}
