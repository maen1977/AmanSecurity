package com.aman.security.security

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build


data class SpywareAppFinding(
    val appName: String,
    val packageName: String,
    val assessment: SpywareRiskAssessment
)

data class SpywareAuditSummary(
    val scannedApps: Int,
    val reviewApps: Int,
    val highRiskApps: Int,
    val findings: List<SpywareAppFinding>
)

class SpywareAuditor(private val context: Context) {
    private val packageManager = context.packageManager

    fun audit(): SpywareAuditSummary {
        val packages = installedPackages().filterNot(::isSystemPackage).filter { it.packageName != context.packageName }
        val findings = packages.mapNotNull(::evaluatePackage).filter { it.assessment.level != SpywareReviewLevel.LOW }
            .sortedWith(compareByDescending<SpywareAppFinding> { it.assessment.level }.thenByDescending { it.assessment.score })
        return SpywareAuditSummary(
            scannedApps = packages.size,
            reviewApps = findings.count { it.assessment.level == SpywareReviewLevel.REVIEW },
            highRiskApps = findings.count { it.assessment.level == SpywareReviewLevel.HIGH },
            findings = findings
        )
    }

    fun auditPackage(packageName: String): SpywareAppFinding? = packageInfo(packageName)?.let(::evaluatePackage)

    private fun evaluatePackage(info: PackageInfo): SpywareAppFinding? {
        val signals = linkedSetOf<SpywareCapabilitySignal>()
        if (info.services.orEmpty().any { it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE }) {
            signals += SpywareCapabilitySignal.ACCESSIBILITY_SERVICE
        }
        if (info.services.orEmpty().any { it.permission == Manifest.permission.BIND_NOTIFICATION_LISTENER_SERVICE }) {
            signals += SpywareCapabilitySignal.NOTIFICATION_LISTENER
        }
        if (info.receivers.orEmpty().any { it.permission == Manifest.permission.BIND_DEVICE_ADMIN }) {
            signals += SpywareCapabilitySignal.DEVICE_ADMIN
        }
        val requested = info.requestedPermissions?.toSet().orEmpty()
        if (Manifest.permission.RECEIVE_BOOT_COMPLETED in requested) signals += SpywareCapabilitySignal.BOOT_PERSISTENCE
        if (Manifest.permission.SYSTEM_ALERT_WINDOW in requested) signals += SpywareCapabilitySignal.OVERLAY_DECLARED
        if (isGranted(info.packageName, Manifest.permission.READ_SMS)) signals += SpywareCapabilitySignal.SMS_ACCESS
        if (isGranted(info.packageName, Manifest.permission.READ_CALL_LOG)) signals += SpywareCapabilitySignal.CALL_LOG_ACCESS
        if (isGranted(info.packageName, Manifest.permission.ACCESS_FINE_LOCATION) || isGranted(info.packageName, Manifest.permission.ACCESS_COARSE_LOCATION)) {
            signals += SpywareCapabilitySignal.LOCATION_ACCESS
        }
        if (isGranted(info.packageName, Manifest.permission.RECORD_AUDIO)) signals += SpywareCapabilitySignal.MICROPHONE_ACCESS
        if (isGranted(info.packageName, Manifest.permission.READ_CONTACTS)) signals += SpywareCapabilitySignal.CONTACTS_ACCESS
        if (isConfirmedSideload(info.packageName)) signals += SpywareCapabilitySignal.SIDELOADED

        val assessment = SpywareRiskPolicy.evaluate(signals)
        val appName = runCatching { info.applicationInfo?.loadLabel(packageManager)?.toString().orEmpty() }
            .getOrDefault("").ifBlank { info.packageName }
        return SpywareAppFinding(appName, info.packageName, assessment)
    }

    private fun isGranted(packageName: String, permission: String): Boolean =
        packageManager.checkPermission(permission, packageName) == PackageManager.PERMISSION_GRANTED

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

    private fun installedPackages(): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") packageManager.getInstalledPackages(flags)
            }
        }.getOrDefault(emptyList())
    }

    private fun packageInfo(packageName: String): PackageInfo? {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") packageManager.getPackageInfo(packageName, flags)
            }
        }.getOrNull()
    }

    private fun isSystemPackage(info: PackageInfo): Boolean {
        val flags = info.applicationInfo?.flags ?: return false
        return flags and ApplicationInfo.FLAG_SYSTEM != 0 || flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }
}
