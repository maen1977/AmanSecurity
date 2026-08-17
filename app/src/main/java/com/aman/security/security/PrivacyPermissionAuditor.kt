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
        val reviewApps = allUserApps.filter(PrivacyPermissionReviewPolicy::shouldReview)
        val elevated = reviewApps.size
        val totalGranted = exposed.sumOf { it.grantedSensitivePermissions }

        val findings = buildList {
            if (reviewApps.isNotEmpty()) add(SecurityAuditFinding("privacy_permission_review", SecurityAuditSeverity.WARNING))
            else if (exposed.isNotEmpty()) add(SecurityAuditFinding("privacy_permission_inventory", SecurityAuditSeverity.INFO))
        }
        return PrivacyPermissionAudit(
            scannedApps = allUserApps.size,
            appsWithSensitivePermissions = exposed.size,
            elevatedPermissionApps = elevated,
            totalGrantedSensitivePermissions = totalGranted,
            findings = findings,
            reviewApps = reviewApps
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
            grantedPermissions = grantedPermissions,
            isTrustedInstall = isTrustedStoreInstall(info.packageName)
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

    private fun isTrustedStoreInstall(packageName: String): Boolean = runCatching {
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstallerPackageName(packageName)
        }
        PrivacyPermissionReviewPolicy.isTrustedInstaller(installer)
    }.getOrDefault(false)

    companion object {
        private const val ELEVATED_PERMISSION_THRESHOLD = PrivacyPermissionReviewPolicy.ELEVATED_PERMISSION_THRESHOLD
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

/**
 * A privacy permission is a review signal only when it is attached to an app
 * whose install provenance is not a recognized app store. Store provenance
 * suppresses this capability-only review; confirmed malware and independent
 * package/signature findings continue through their own detection paths.
 */
internal object PrivacyPermissionReviewPolicy {
    const val ELEVATED_PERMISSION_THRESHOLD = 5

    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending", // Google Play Store
        "com.samsung.android.app.galaxyapps", // Samsung Galaxy Store
        "com.amazon.venezia", // Amazon Appstore
        "com.huawei.appmarket", // Huawei AppGallery
        "com.oppo.market", // OPPO App Market
        "com.vivo.appstore", // vivo App Store
        "com.xiaomi.mipicks", // Xiaomi GetApps
        "com.heytap.market", // HeyTap App Market
        "com.transsion.market" // Transsion App Store
    )

    fun shouldReview(app: PrivacyAppExposure): Boolean =
        app.grantedSensitivePermissions >= ELEVATED_PERMISSION_THRESHOLD && !app.isTrustedInstall

    fun isTrustedInstaller(installerPackageName: String?): Boolean =
        installerPackageName?.trim()?.lowercase() in TRUSTED_INSTALLERS
}
