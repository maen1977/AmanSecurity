package com.aman.security.security

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build

class PrivacyPermissionAuditor(private val context: Context) {
    private val packageManager = context.packageManager

    fun audit(): PrivacyPermissionAudit {
        val allUserApps = userAppExposure(includeZero = true)
        val exposed = allUserApps.filter { it.grantedSensitivePermissions > 0 }
        val elevated = exposed.count { it.grantedSensitivePermissions >= ELEVATED_PERMISSION_THRESHOLD }
        val totalGranted = exposed.sumOf { it.grantedSensitivePermissions }

        val findings = buildList {
            if (elevated > 0) add(SecurityAuditFinding("privacy_permission_review", SecurityAuditSeverity.WARNING))
            else if (exposed.isNotEmpty()) add(SecurityAuditFinding("privacy_permission_inventory", SecurityAuditSeverity.INFO))
        }
        return PrivacyPermissionAudit(
            scannedApps = allUserApps.size,
            appsWithSensitivePermissions = exposed.size,
            elevatedPermissionApps = elevated,
            totalGrantedSensitivePermissions = totalGranted,
            findings = findings,
            reviewApps = allUserApps
                .filter { it.grantedSensitivePermissions >= ELEVATED_PERMISSION_THRESHOLD }
                .sortedWith(compareByDescending<PrivacyAppExposure> { it.grantedSensitivePermissions }.thenBy { it.appName.lowercase() })
        )
    }

    fun appsForReview(): List<PrivacyAppExposure> = userAppExposure(includeZero = false)
        .sortedWith(compareByDescending<PrivacyAppExposure> { it.grantedSensitivePermissions }.thenBy { it.appName.lowercase() })

    private fun userAppExposure(includeZero: Boolean): List<PrivacyAppExposure> = installedPackages().mapNotNull { info ->
        if (info.packageName == context.packageName || isSystemPackage(info)) return@mapNotNull null
        val grantedPermissions = SENSITIVE_PERMISSIONS.filter { permission ->
            packageManager.checkPermission(permission, info.packageName) == PackageManager.PERMISSION_GRANTED
        }
        val granted = grantedPermissions.size
        if (!includeZero && granted == 0) return@mapNotNull null
        val appName = runCatching {
            info.applicationInfo?.loadLabel(packageManager)?.toString().orEmpty()
        }.getOrDefault("").ifBlank { info.packageName }
        PrivacyAppExposure(
            appName = appName,
            packageName = info.packageName,
            grantedSensitivePermissions = granted,
            grantedPermissions = grantedPermissions
        )
    }

    private fun installedPackages(): List<PackageInfo> = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION") packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }
    }.getOrDefault(emptyList())

    private fun isSystemPackage(info: PackageInfo): Boolean {
        val flags = info.applicationInfo?.flags ?: return false
        return flags and ApplicationInfo.FLAG_SYSTEM != 0 || flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }

    companion object {
        private const val ELEVATED_PERMISSION_THRESHOLD = 5
        private val SENSITIVE_PERMISSIONS = listOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.READ_CALENDAR,
            Manifest.permission.BODY_SENSORS,
            Manifest.permission.READ_CALL_LOG,
            Manifest.permission.READ_SMS
        )
    }
}
