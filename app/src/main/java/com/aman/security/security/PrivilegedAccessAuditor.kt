package com.aman.security.security

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationManagerCompat

/**
 * Reviews privileged Android control surfaces that are commonly abused by stalkerware,
 * banking malware and remote-control tools. This is a capability audit only: a granted
 * privilege is never treated as malware by itself.
 */
enum class PrivilegedAccessKind {
    ACCESSIBILITY,
    NOTIFICATION_LISTENER,
    DEVICE_ADMIN,
    OVERLAY
}

data class PrivilegedAccessApp(
    val appName: String,
    val packageName: String,
    val kinds: Set<PrivilegedAccessKind>,
    val systemApp: Boolean,
    val sideloaded: Boolean
)

data class PrivilegedAccessSnapshot(
    val apps: List<PrivilegedAccessApp>
) {
    fun byPackage(): Map<String, PrivilegedAccessApp> = apps.associateBy { it.packageName }
}

class PrivilegedAccessAuditor(private val context: Context) {
    private val packageManager = context.packageManager

    fun audit(): PrivilegedAccessSnapshot {
        val enabledAccessibility = enabledAccessibilityPackages()
        val enabledListeners = NotificationManagerCompat.getEnabledListenerPackages(context)
        val activeAdmins = activeDeviceAdminPackages()
        val packages = installedPackages()

        val apps = packages.mapNotNull { info ->
            val packageName = info.packageName
            if (packageName == context.packageName) return@mapNotNull null
            val kinds = linkedSetOf<PrivilegedAccessKind>()
            if (packageName in enabledAccessibility) kinds += PrivilegedAccessKind.ACCESSIBILITY
            if (packageName in enabledListeners) kinds += PrivilegedAccessKind.NOTIFICATION_LISTENER
            if (packageName in activeAdmins) kinds += PrivilegedAccessKind.DEVICE_ADMIN
            if (hasGrantedOverlay(info)) kinds += PrivilegedAccessKind.OVERLAY
            if (kinds.isEmpty()) return@mapNotNull null

            val appInfo = info.applicationInfo
            val label = runCatching { appInfo?.loadLabel(packageManager)?.toString().orEmpty() }
                .getOrDefault("").ifBlank { packageName }
            PrivilegedAccessApp(
                appName = label,
                packageName = packageName,
                kinds = kinds,
                systemApp = isSystemApp(appInfo),
                sideloaded = isConfirmedSideload(packageName)
            )
        }.sortedWith(
            compareByDescending<PrivilegedAccessApp> { it.kinds.size }
                .thenBy { it.appName.lowercase() }
        )
        return PrivilegedAccessSnapshot(apps)
    }

    private fun enabledAccessibilityPackages(): Set<String> {
        val manager = context.getSystemService(AccessibilityManager::class.java) ?: return emptySet()
        return runCatching {
            manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }
                .toSet()
        }.getOrDefault(emptySet())
    }

    private fun activeDeviceAdminPackages(): Set<String> {
        val manager = context.getSystemService(DevicePolicyManager::class.java) ?: return emptySet()
        return runCatching { manager.activeAdmins.orEmpty().map { it.packageName }.toSet() }
            .getOrDefault(emptySet())
    }

    private fun installedPackages(): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") packageManager.getInstalledPackages(flags)
            }
        }.getOrDefault(emptyList())
    }

    private fun hasGrantedOverlay(info: PackageInfo): Boolean {
        val requested = info.requestedPermissions.orEmpty()
        if (Manifest.permission.SYSTEM_ALERT_WINDOW !in requested) return false
        val appInfo = info.applicationInfo ?: return false
        val appOps = context.getSystemService(AppOpsManager::class.java) ?: return false
        return runCatching {
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                appInfo.uid,
                info.packageName
            ) == AppOpsManager.MODE_ALLOWED
        }.getOrDefault(false)
    }

    private fun isConfirmedSideload(packageName: String): Boolean = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            when (packageManager.getInstallSourceInfo(packageName).packageSource) {
                PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE,
                PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE -> true
                else -> false
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val installer = packageManager.getInstallSourceInfo(packageName).installingPackageName
            installer == "com.google.android.packageinstaller" || installer == "com.android.packageinstaller"
        } else {
            @Suppress("DEPRECATION")
            val installer = packageManager.getInstallerPackageName(packageName)
            installer == "com.google.android.packageinstaller" || installer == "com.android.packageinstaller"
        }
    }.getOrDefault(false)

    private fun isSystemApp(info: ApplicationInfo?): Boolean {
        val flags = info?.flags ?: return false
        return flags and ApplicationInfo.FLAG_SYSTEM != 0 ||
            flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }
}
