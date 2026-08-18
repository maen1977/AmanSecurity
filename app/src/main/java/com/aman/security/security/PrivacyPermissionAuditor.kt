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
        val installSource = installSource(info.packageName)
        PrivacyAppExposure(
            appName = appName,
            packageName = info.packageName,
            grantedSensitivePermissions = granted,
            grantedPermissions = grantedPermissions,
            isTrustedInstall = isTrustedStoreInstall(installSource),
            installSource = installSource
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

    private fun installSource(packageName: String): String = runCatching {
        val sourceInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            packageManager.getInstallSourceInfo(packageName)
        } else {
            null
        }
        val installerIsTrusted = sourceInfo?.installingPackageName?.let {
            PrivacyPermissionReviewPolicy.isTrustedInstaller(it)
        } == true
        when {
            installerIsTrusted -> "STORE"
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && sourceInfo != null -> when (sourceInfo.packageSource) {
                android.content.pm.PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE -> "LOCAL_FILE"
                android.content.pm.PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE -> "DOWNLOADED_FILE"
                android.content.pm.PackageInstaller.PACKAGE_SOURCE_OTHER -> "OTHER"
                android.content.pm.PackageInstaller.PACKAGE_SOURCE_STORE -> "STORE"
                else -> "UNKNOWN"
            }
            sourceInfo != null -> if (sourceInfo.installingPackageName.isNullOrBlank()) "UNKNOWN" else "OTHER"
            else -> {
                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(packageName)?.let { installer ->
                    if (PrivacyPermissionReviewPolicy.isTrustedInstaller(installer)) "STORE" else "OTHER"
                } ?: "UNKNOWN"
            }
        }
    }.getOrDefault("UNKNOWN")

    private fun isTrustedStoreInstall(installSource: String): Boolean = installSource == "STORE"

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
        app.grantedSensitivePermissions >= ELEVATED_PERMISSION_THRESHOLD &&
            !app.isTrustedInstall &&
            !(isKnownOfficialPackage(app.packageName) && app.installSource in NON_PROVENANCE_SOURCES)

    fun isTrustedInstaller(installerPackageName: String?): Boolean =
        installerPackageName?.trim()?.lowercase() in TRUSTED_INSTALLERS

    fun isKnownOfficialPackage(packageName: String): Boolean =
        packageName.trim().lowercase() in OFFICIAL_CAPABILITY_ONLY_PACKAGES

    private val NON_PROVENANCE_SOURCES = setOf("UNKNOWN", "OTHER")

    private val OFFICIAL_CAPABILITY_ONLY_PACKAGES = setOf(
        // Meta / WhatsApp official packages.
        "com.whatsapp",
        "com.whatsapp.w4b",
        "com.facebook.orca", // Messenger
        // Official Telegram and caller-ID applications.
        "org.telegram.messenger",
        "org.telegram.messenger.web",
        "com.truecaller",
        // Google productivity and device-finding applications.
        "com.google.android.apps.docs",
        "com.google.android.apps.adm", // Find My Device / Find Hub legacy package
        "com.google.android.apps.findmydevice",
        // Built-in and vendor screen-recording packages.
        "com.miui.screenrecorder",
        "com.android.screenrecord",
        "com.samsung.android.app.screenrecorder",
        "com.sec.android.app.screencapture",
        "com.huawei.screenrecorder",
        "com.oplus.screenrecorder",
        "com.coloros.screenrecorder",
        "com.vivo.screenrecorder"
    )
}
