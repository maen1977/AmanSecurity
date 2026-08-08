package com.aman.security.scanner

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

class InstalledAppScanner(
    private val context: Context,
    private val database: SignatureDatabase
) {
    private val packageManager: PackageManager = context.packageManager

    fun scanUserApps(): InstalledAppsScanSummary {
        val packages = installedPackages()
            .asSequence()
            .filter { it.packageName != context.packageName }
            .filterNot(::isSystemPackage)
            .map(::scanPackage)
            .sortedWith(compareByDescending<InstalledAppScanResult> { it.riskScore }.thenBy { it.appName.lowercase() })
            .toList()

        val review = packages.count { it.riskLevel == AppRiskLevel.MEDIUM || it.riskLevel == AppRiskLevel.HIGH || it.riskLevel == AppRiskLevel.KNOWN_THREAT }
        val high = packages.count { it.riskLevel == AppRiskLevel.HIGH }
        val known = packages.count { it.riskLevel == AppRiskLevel.KNOWN_THREAT }

        return InstalledAppsScanSummary(
            scannedApps = packages.size,
            reviewApps = review,
            highRiskApps = high,
            knownThreats = known,
            results = packages
        )
    }

    private fun installedPackages(): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_SIGNING_CERTIFICATES
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstalledPackages(flags)
        }
    }

    private fun scanPackage(packageInfo: PackageInfo): InstalledAppScanResult {
        val applicationInfo = packageInfo.applicationInfo
        val appName = applicationInfo?.let { packageManager.getApplicationLabel(it).toString() }
            ?.takeIf { it.isNotBlank() }
            ?: packageInfo.packageName
        val source = installSource(packageInfo.packageName)
        val requestedPermissions = packageInfo.requestedPermissions?.toSet().orEmpty()
        val hasAccessibilityService = packageInfo.services?.any {
            it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE
        } == true

        val apkSha256 = applicationInfo?.sourceDir
            ?.let { runCatching { hashFile(File(it)) }.getOrNull() }
        val threat = apkSha256?.let(database::find)
        val evaluation = AppRiskEvaluator.evaluate(
            AppRiskInput(
                requestedPermissions = requestedPermissions,
                hasAccessibilityService = hasAccessibilityService,
                installSource = source,
                knownThreatReference = threat?.id
            )
        )

        return InstalledAppScanResult(
            appName = appName,
            packageName = packageInfo.packageName,
            versionName = packageInfo.versionName,
            installSource = source,
            riskScore = evaluation.score,
            riskLevel = evaluation.level,
            signals = evaluation.signals,
            apkSha256 = apkSha256,
            signingCertificateSha256 = signingCertificateSha256(packageInfo),
            threatReference = threat?.id
        )
    }

    private fun isSystemPackage(packageInfo: PackageInfo): Boolean {
        val flags = packageInfo.applicationInfo?.flags ?: return false
        return flags and ApplicationInfo.FLAG_SYSTEM != 0 || flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }

    private fun installSource(packageName: String): AppInstallSource {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                when (packageManager.getInstallSourceInfo(packageName).packageSource) {
                    PackageInstaller.PACKAGE_SOURCE_STORE -> AppInstallSource.STORE
                    PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE -> AppInstallSource.LOCAL_FILE
                    PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE -> AppInstallSource.DOWNLOADED_FILE
                    PackageInstaller.PACKAGE_SOURCE_OTHER -> AppInstallSource.OTHER
                    else -> AppInstallSource.UNKNOWN
                }
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                classifyInstallerPackage(packageManager.getInstallSourceInfo(packageName).installingPackageName)
            } else {
                @Suppress("DEPRECATION")
                classifyInstallerPackage(packageManager.getInstallerPackageName(packageName))
            }
        }.getOrDefault(AppInstallSource.UNKNOWN)
    }

    private fun classifyInstallerPackage(installerPackage: String?): AppInstallSource {
        if (installerPackage.isNullOrBlank()) return AppInstallSource.UNKNOWN
        return when (installerPackage) {
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.huawei.appmarket",
            "com.amazon.venezia" -> AppInstallSource.STORE
            "com.google.android.packageinstaller",
            "com.android.packageinstaller" -> AppInstallSource.LOCAL_FILE
            else -> AppInstallSource.OTHER
        }
    }

    private fun hashFile(file: File): String = FileInputStream(file).use(Sha256::fromStream)

    private fun signingCertificateSha256(packageInfo: PackageInfo): String? {
        val signerBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = packageInfo.signingInfo ?: return null
            val signers = if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }
            signers.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures?.firstOrNull()?.toByteArray()
        } ?: return null

        return MessageDigest.getInstance("SHA-256")
            .digest(signerBytes)
            .joinToString(separator = "") { byte -> "%02x".format(byte) }
    }
}
