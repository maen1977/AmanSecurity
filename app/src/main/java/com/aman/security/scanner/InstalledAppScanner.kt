package com.aman.security.scanner

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import com.aman.security.detection.DetectionFinding
import com.aman.security.detection.DetectionSource
import com.aman.security.detection.DetectionVerdictLevel
import com.aman.security.detection.FindingConfidence
import com.aman.security.detection.ImpersonationDetector
import com.aman.security.detection.ReputationDisposition
import com.aman.security.detection.ReputationKind
import com.aman.security.detection.ThreatFamily
import com.aman.security.detection.ThreatGraphEngine
import com.aman.security.detection.VerdictEngine
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

class InstalledAppScanner(
    private val context: Context,
    private val database: SignatureDatabase
) {
    private val packageManager: PackageManager = context.packageManager
    private val deepAnalyzer by lazy { ApkStaticAnalyzer(context, database) }

    fun scanUserApps(
        deep: Boolean = true,
        onProgress: ((completed: Int, total: Int, appName: String, packageName: String) -> Unit)? = null
    ): InstalledAppsScanSummary {
        val candidates = installedPackages()
            .filter { it.packageName != context.packageName }
            .filterNot(::isSystemPackage)
        val total = candidates.size
        val scanned = ArrayList<InstalledAppScanResult>(total)
        candidates.forEachIndexed { index, packageInfo ->
            val appName = packageInfo.applicationInfo
                ?.let { packageManager.getApplicationLabel(it).toString() }
                ?.takeIf { it.isNotBlank() }
                ?: packageInfo.packageName
            onProgress?.invoke(index, total, appName, packageInfo.packageName)
            scanned += scanPackage(packageInfo, deep = deep)
            onProgress?.invoke(index + 1, total, appName, packageInfo.packageName)
        }
        val packages = scanned.sortedWith(
            compareByDescending<InstalledAppScanResult> { it.riskScore }.thenBy { it.appName.lowercase() }
        )
        val review = packages.count { it.riskLevel != AppRiskLevel.LOW }
        val high = packages.count { it.riskLevel == AppRiskLevel.HIGH }
        val known = packages.count { it.riskLevel == AppRiskLevel.KNOWN_THREAT }
        return InstalledAppsScanSummary(packages.size, review, high, known, packages)
    }

    fun scanPackageByName(packageName: String, deep: Boolean = true): InstalledAppScanResult? {
        if (packageName == context.packageName) return null
        val packageInfo = packageInfo(packageName) ?: return null
        if (isSystemPackage(packageInfo)) return null
        return scanPackage(packageInfo, deep)
    }

    private fun packageInfo(packageName: String): PackageInfo? {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or signingInfoFlag()
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") packageManager.getPackageInfo(packageName, flags)
            }
        }.getOrNull()
    }

    private fun installedPackages(): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or signingInfoFlag()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION") packageManager.getInstalledPackages(flags)
        }
    }


    @Suppress("DEPRECATION")
    private fun signingInfoFlag(): Int = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        PackageManager.GET_SIGNING_CERTIFICATES
    } else {
        PackageManager.GET_SIGNATURES
    }

    private fun scanPackage(packageInfo: PackageInfo, deep: Boolean): InstalledAppScanResult {
        val applicationInfo = packageInfo.applicationInfo
        val appName = applicationInfo?.let { packageManager.getApplicationLabel(it).toString() }?.takeIf { it.isNotBlank() } ?: packageInfo.packageName
        val source = installSource(packageInfo.packageName)
        val requestedPermissions = packageInfo.requestedPermissions?.toSet().orEmpty()
        val hasAccessibilityService = packageInfo.services?.any { it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE } == true
        val apkFile = applicationInfo?.sourceDir?.let(::File)
        val apkSha256 = apkFile?.let { runCatching { hashFile(it) }.getOrNull() }
        val signerHash = signingCertificateSha256(packageInfo)
        val fileThreat = apkSha256?.let(database::find)?.takeIf { it.classification == ScanClassification.KNOWN_THREAT }
        val signerThreat = signerHash?.let { database.findApk(ApkIndicatorKind.SIGNER, it) }?.takeIf { it.classification == ApkIdentityClassification.KNOWN_THREAT }
        val packageHash = sha256Text(packageInfo.packageName)
        val packageThreat = database.findApk(ApkIndicatorKind.PACKAGE, packageHash)?.takeIf { it.classification == ApkIdentityClassification.KNOWN_THREAT }
        val legacyThreatReference = fileThreat?.id ?: signerThreat?.id ?: packageThreat?.id

        val basic = AppRiskEvaluator.evaluate(AppRiskInput(requestedPermissions, hasAccessibilityService, source, legacyThreatReference))
        val findings = mutableListOf<DetectionFinding>()
        if (legacyThreatReference != null) {
            val family = database.detectionRuleset.findMetadata(legacyThreatReference)?.family
                ?.takeUnless { it == ThreatFamily.UNKNOWN || it == ThreatFamily.TEST }
                ?: ThreatFamily.MALWARE
            findings += DetectionFinding(legacyThreatReference, DetectionSource.REPUTATION, 100, FindingConfidence.CONFIRMED, family, legacyThreatReference)
        } else if (basic.score >= 55) {
            findings += DetectionFinding("INSTALLED_PERMISSION_CLUSTER", DetectionSource.MANIFEST, 26, FindingConfidence.MEDIUM, ThreatFamily.RISKWARE)
        } else if (basic.score >= 20) {
            findings += DetectionFinding("INSTALLED_PERMISSION_REVIEW", DetectionSource.MANIFEST, 10, FindingConfidence.LOW, ThreatFamily.RISKWARE)
        }
        val signerReputation = signerHash?.let { database.findReputation(ReputationKind.SIGNER, it) }
        val packageReputation = database.findReputation(ReputationKind.PACKAGE, packageHash)
        val fileReputation = apkSha256?.let { database.findReputation(ReputationKind.FILE, it) }
        signerReputation?.toFinding()?.let(findings::add)
        packageReputation?.toFinding()?.let(findings::add)
        fileReputation?.toFinding()?.let(findings::add)
        val impersonationFindings = ImpersonationDetector.evaluate(
            packageInfo.packageName,
            appName,
            database.detectionRuleset.brands,
            signerSha256 = signerHash,
            isSideloaded = source == AppInstallSource.LOCAL_FILE || source == AppInstallSource.DOWNLOADED_FILE
        )
        findings += impersonationFindings
        if (impersonationFindings.isNotEmpty() && AppRiskSignal.NON_STORE_INSTALL in basic.signals) {
            findings += DetectionFinding(
                "IMPERSONATION_SIDELOAD",
                DetectionSource.IMPERSONATION,
                20,
                FindingConfidence.MEDIUM,
                ThreatFamily.PHISHING
            )
        }
        val trustedAllowlist = signerReputation?.disposition == ReputationDisposition.SAFE ||
            fileReputation?.disposition == ReputationDisposition.SAFE

        val deepAnalysis = if (deep && apkFile != null && apkSha256 != null) deepAnalyzer.analyzeInstalledFile(apkFile, apkSha256) else null
        deepAnalysis?.advancedVerdict?.findings?.let(findings::addAll)
        findings += ThreatGraphEngine.correlate(findings, database.detectionRuleset.graphLinks)
        val verdict = VerdictEngine.evaluate(findings, allowlisted = trustedAllowlist)

        // Malware detection and privacy/capability review are deliberately separate. Camera,
        // microphone, contacts, boot, overlay, etc. belong in Permissions Control; they do not
        // increase the antivirus verdict shown on the Scan page. The installed-app malware score
        // is therefore the multi-engine verdict only.
        val finalScore = verdict.score.coerceIn(0, 100)
        val finalLevel = when {
            verdict.level == DetectionVerdictLevel.KNOWN_THREAT -> AppRiskLevel.KNOWN_THREAT
            verdict.level == DetectionVerdictLevel.VERY_HIGH || verdict.level == DetectionVerdictLevel.HIGH -> AppRiskLevel.HIGH
            verdict.level == DetectionVerdictLevel.REVIEW -> AppRiskLevel.MEDIUM
            else -> AppRiskLevel.LOW
        }
        val threatReference = verdict.confirmedReference ?: legacyThreatReference

        return InstalledAppScanResult(
            appName = appName,
            packageName = packageInfo.packageName,
            versionName = packageInfo.versionName,
            installSource = source,
            riskScore = finalScore,
            riskLevel = finalLevel,
            signals = basic.signals,
            apkSha256 = apkSha256,
            signingCertificateSha256 = signerHash,
            threatReference = threatReference,
            advancedVerdict = verdict,
            deepAnalysisPerformed = deepAnalysis != null
        )
    }

    private fun com.aman.security.detection.ReputationIndicator.toFinding(): DetectionFinding? = when (disposition) {
        ReputationDisposition.SAFE -> null
        ReputationDisposition.TEST -> DetectionFinding(id, DetectionSource.REPUTATION, 0, FindingConfidence.CONFIRMED, ThreatFamily.TEST, id)
        ReputationDisposition.MALICIOUS -> DetectionFinding(id, DetectionSource.REPUTATION, 100, confidence, family, id)
    }

    private fun isSystemPackage(packageInfo: PackageInfo): Boolean {
        val flags = packageInfo.applicationInfo?.flags ?: return false
        return flags and ApplicationInfo.FLAG_SYSTEM != 0 || flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }

    private fun installSource(packageName: String): AppInstallSource = runCatching {
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
            @Suppress("DEPRECATION") classifyInstallerPackage(packageManager.getInstallerPackageName(packageName))
        }
    }.getOrDefault(AppInstallSource.UNKNOWN)

    private fun classifyInstallerPackage(installerPackage: String?): AppInstallSource {
        if (installerPackage.isNullOrBlank()) return AppInstallSource.UNKNOWN
        return when (installerPackage) {
            "com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket", "com.amazon.venezia" -> AppInstallSource.STORE
            "com.google.android.packageinstaller", "com.android.packageinstaller" -> AppInstallSource.LOCAL_FILE
            else -> AppInstallSource.OTHER
        }
    }

    private fun hashFile(file: File): String = FileInputStream(file).use { Sha256.fromStream(it) }
    private fun sha256Text(value: String): String = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    private fun signingCertificateSha256(packageInfo: PackageInfo): String? {
        val signerBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = packageInfo.signingInfo ?: return null
            val signers = if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners else signingInfo.signingCertificateHistory
            signers.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION") packageInfo.signatures?.firstOrNull()?.toByteArray()
        } ?: return null
        return MessageDigest.getInstance("SHA-256").digest(signerBytes).joinToString("") { "%02x".format(it) }
    }
}
