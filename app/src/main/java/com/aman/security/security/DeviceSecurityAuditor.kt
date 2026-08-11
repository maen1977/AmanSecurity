package com.aman.security.security

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import java.io.File

class DeviceSecurityAuditor(private val context: Context) {
    fun audit(): DeviceSecurityAudit {
        val resolver = context.contentResolver
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        val screenLockSecure = keyguard?.isDeviceSecure == true
        val developerOptionsEnabled = readGlobal(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        val adbEnabled = readGlobal(Settings.Global.ADB_ENABLED, 0) == 1
        val automaticTimeEnabled = readGlobal(Settings.Global.AUTO_TIME, 1) == 1
        val automaticTimeZoneEnabled = readGlobal(Settings.Global.AUTO_TIME_ZONE, 1) == 1
        val rootSignals = rootSignalCount()

        val findings = buildList {
            if (!screenLockSecure) add(SecurityAuditFinding("screen_lock", SecurityAuditSeverity.HIGH))
            if (rootSignals > 0) add(SecurityAuditFinding("root_signals", SecurityAuditSeverity.HIGH))
            if (adbEnabled) add(SecurityAuditFinding("adb", SecurityAuditSeverity.WARNING))
            if (developerOptionsEnabled) add(SecurityAuditFinding("developer_options", SecurityAuditSeverity.WARNING))
            if (!automaticTimeEnabled) add(SecurityAuditFinding("automatic_time", SecurityAuditSeverity.WARNING))
            if (!automaticTimeZoneEnabled) add(SecurityAuditFinding("automatic_timezone", SecurityAuditSeverity.INFO))
        }

        return DeviceSecurityAudit(
            screenLockSecure = screenLockSecure,
            developerOptionsEnabled = developerOptionsEnabled,
            adbEnabled = adbEnabled,
            automaticTimeEnabled = automaticTimeEnabled,
            automaticTimeZoneEnabled = automaticTimeZoneEnabled,
            rootSignals = rootSignals,
            securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty(),
            findings = findings
        )
    }

    private fun readGlobal(name: String, fallback: Int): Int = runCatching {
        Settings.Global.getInt(context.contentResolver, name, fallback)
    }.getOrDefault(fallback)

    /** Heuristic only: visibility of these paths varies by Android/OEM. */
    private fun rootSignalCount(): Int {
        var signals = 0
        val tags = Build.TAGS.orEmpty().lowercase()
        if ("test-keys" in tags) signals++
        val paths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/app/Magisk.apk",
            "/data/adb/magisk"
        )
        signals += paths.count { path -> runCatching { File(path).exists() }.getOrDefault(false) }
        return signals
    }
}
