package com.aman.security.security

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build


enum class BackgroundActivityLevel {
    REVIEW,
    HIGH
}

enum class BackgroundActivitySignal {
    FOREGROUND_SERVICE,
    START_ON_BOOT,
    SENSITIVE_SENSOR,
    OVERLAY_CAPABILITY,
    VPN_SERVICE,
    MULTIPLE_SERVICES,
    SIDELOADED
}

data class BackgroundActivityAssessment(
    val level: BackgroundActivityLevel,
    val score: Int,
    val signals: Set<BackgroundActivitySignal>
)

data class BackgroundActivityFinding(
    val appName: String,
    val packageName: String,
    val serviceCount: Int,
    val assessment: BackgroundActivityAssessment
)

data class BackgroundActivitySummary(
    val scannedApps: Int,
    val reviewApps: Int,
    val highImpactApps: Int,
    val findings: List<BackgroundActivityFinding>
)

/**
 * Conservative capability review for apps that may keep work alive in the background.
 * It does not claim to measure milliamp-hours and never stops or disables another app.
 */
class BackgroundActivityAuditor(private val context: Context) {
    private val packageManager = context.packageManager

    fun audit(): BackgroundActivitySummary {
        val packages = installedPackages()
            .filterNot(::isSystemPackage)
            .filter { it.packageName != context.packageName }
        val findings = packages.mapNotNull(::evaluatePackage)
            .sortedWith(compareByDescending<BackgroundActivityFinding> { it.assessment.level }
                .thenByDescending { it.assessment.score })
        return BackgroundActivitySummary(
            scannedApps = packages.size,
            reviewApps = findings.count { it.assessment.level == BackgroundActivityLevel.REVIEW },
            highImpactApps = findings.count { it.assessment.level == BackgroundActivityLevel.HIGH },
            findings = findings
        )
    }

    private fun evaluatePackage(info: PackageInfo): BackgroundActivityFinding? {
        val services = info.services.orEmpty()
        val requested = info.requestedPermissions?.toSet().orEmpty()
        val foregroundService = services.any { service ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) service.foregroundServiceType != 0
            else Manifest.permission.FOREGROUND_SERVICE in requested
        }
        val startsOnBoot = Manifest.permission.RECEIVE_BOOT_COMPLETED in requested
        val sensitiveSensor = requested.any {
            it == Manifest.permission.ACCESS_FINE_LOCATION ||
                it == Manifest.permission.ACCESS_COARSE_LOCATION ||
                it == Manifest.permission.RECORD_AUDIO ||
                it == Manifest.permission.CAMERA
        }
        val overlay = Manifest.permission.SYSTEM_ALERT_WINDOW in requested
        val vpn = services.any { it.permission == Manifest.permission.BIND_VPN_SERVICE }
        val multipleServices = services.size >= 3
        val sideloaded = runCatching { SpywareAuditor(context).auditPackage(info.packageName) }
            .getOrNull()?.assessment?.signals?.contains(SpywareCapabilitySignal.SIDELOADED) == true

        val signals = linkedSetOf<BackgroundActivitySignal>()
        if (foregroundService) signals += BackgroundActivitySignal.FOREGROUND_SERVICE
        if (startsOnBoot) signals += BackgroundActivitySignal.START_ON_BOOT
        if (sensitiveSensor) signals += BackgroundActivitySignal.SENSITIVE_SENSOR
        if (overlay) signals += BackgroundActivitySignal.OVERLAY_CAPABILITY
        if (vpn) signals += BackgroundActivitySignal.VPN_SERVICE
        if (multipleServices) signals += BackgroundActivitySignal.MULTIPLE_SERVICES
        if (sideloaded) signals += BackgroundActivitySignal.SIDELOADED

        var score = 0
        if (foregroundService) score += 20
        if (startsOnBoot) score += 15
        if (sensitiveSensor) score += 15
        if (overlay) score += 10
        if (vpn) score += 10
        if (multipleServices) score += 15
        if (sideloaded) score += 10

        val high = foregroundService && startsOnBoot && (sensitiveSensor || overlay || vpn) ||
            multipleServices && startsOnBoot && (sensitiveSensor || overlay) && sideloaded
        val review = high ||
            (foregroundService && (sensitiveSensor || overlay || vpn)) ||
            (startsOnBoot && (sensitiveSensor || overlay || multipleServices)) ||
            (sideloaded && multipleServices)
        if (!review) return null

        val level = if (high) BackgroundActivityLevel.HIGH else BackgroundActivityLevel.REVIEW
        val appName = runCatching { info.applicationInfo?.loadLabel(packageManager)?.toString().orEmpty() }
            .getOrDefault("").ifBlank { info.packageName }
        return BackgroundActivityFinding(
            appName = appName,
            packageName = info.packageName,
            serviceCount = services.size,
            assessment = BackgroundActivityAssessment(level, score.coerceIn(0, 100), signals)
        )
    }

    private fun installedPackages(): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") packageManager.getInstalledPackages(flags)
            }
        }.getOrDefault(emptyList())
    }

    private fun isSystemPackage(info: PackageInfo): Boolean {
        val flags = info.applicationInfo?.flags ?: return false
        return flags and ApplicationInfo.FLAG_SYSTEM != 0 || flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }
}
