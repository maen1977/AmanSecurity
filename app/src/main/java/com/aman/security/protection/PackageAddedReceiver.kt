package com.aman.security.protection

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class PackageAddedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_PACKAGE_ADDED && intent.action != Intent.ACTION_PACKAGE_REPLACED) return
        val packageName = intent.data?.schemeSpecificPart?.takeIf { it.isNotBlank() } ?: return
        if (packageName == context.packageName) return
        val preferences = ProtectionPreferences(context)
        if (!preferences.enabled || !preferences.appInstallMonitorEnabled) return
        preferences.markActivity(context.getString(com.aman.security.R.string.activity_app_install_detected, packageName))
        ProtectionScheduler.scanNewPackage(context.applicationContext, packageName)
    }
}
