package com.aman.security.protection

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class PackageAddedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_PACKAGE_ADDED) return
        val packageName = intent.data?.schemeSpecificPart?.takeIf { it.isNotBlank() } ?: return
        if (packageName == context.packageName) return
        if (!ProtectionPreferences(context).enabled) return
        ProtectionScheduler.scanNewPackage(context.applicationContext, packageName)
    }
}
