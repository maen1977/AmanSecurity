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
import com.aman.security.detection.LocalReasoningClassifier
import com.aman.security.detection.ReputationDisposition
import com.aman.security.detection.ReputationKind
import com.aman.security.detection.ThreatFamily
import com.aman.security.detection.ThreatGraphEngine
import com.aman.security.detection.VerdictEngine
import com.aman.security.protection.CachedAppArtifact
import com.aman.security.protection.LocalScanCacheStore
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

class InstalledAppScanner(
    private val context: Context,
    private val database: SignatureDatabase
) {
    private val packageManager: PackageManager = context.packageManager
    private val deepAnalyzer by lazy { ApkStaticAnalyzer(context, database) }
    private val artifactCacheStore = LocalScanCacheStore(context)
    private val artifactCache = artifactCacheStore.loadApps()
    private var artifactCacheDirty = false

    fun scanUserApps(
        deep: Boolean = true,
        onProgress: ((completed: Int, total: Int, appName: String, packageName: String) -> Unit)? = null
    ): InstalledAppsScanSummary = scanInstalledApps(includeSystem = false, deep = deep, onProgress = onProgress)

    fun scanAllApps(
        deep: Boolean = true,
        onProgress: ((completed: Int, total: Int, appName: String, packageName: String) -> Unit)? = null
    ): InstalledAppsScanSummary = scanInstalledApps(includeSystem = true, deep = deep, onProgress = onProgress)

    private fun scanInstalledApps(
        includeSystem: Boolean,
        deep: Boolean,
        onProgress: ((completed: Int, total: Int, appName: String, packageName: String) -> Unit)?
    ): InstalledAppsScanSummary {
        val candidates = installedPackages()
            .filter { it.packageName != context.packageName }
            .filter { includeSystem || !isSystemPackage(it) }
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
        flushArtifactCache()
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
        return scanPackage(packageInfo, deep).also { flushArtifactCache() }
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
        val apkFiles = buildList {
            applicationInfo?.sourceDir?.let(::File)?.let(::add)
            applicationInfo?.splitSourceDirs.orEmpty().map(::File).forEach(::add)
        }.distinctBy { it.absolutePath }
        val metadataFingerprint = appMetadataFingerprint(packageInfo, apkFiles)
        val cachedArtifact = artifactCache[packageInfo.packageName]
            ?.takeIf { it.metadataFingerprint == metadataFingerprint }
        val componentHashes = if (cachedArtifact != null) {
            apkFiles.mapIndexedNotNull { index, file ->
                cachedArtifact.componentHashes.getOrNull(index)?.let { hash -> file to hash }
            }.takeIf { it.size == apkFiles.size } ?: hashComponents(apkFiles)
        } else {
            hashComponents(apkFiles)
        }
        val apkSha256 = componentHashes.firstOrNull()?.second
        val signerHashes = cachedArtifact?.signerHashes?.takeIf { it.isNotEmpty() }
            ?: signingCertificateSha256s(packageInfo)
        val signerHash = signerHashes.firstOrNull()
        val cacheHashes = componentHashes.map { it.second }
        if (cacheHashes.isNotEmpty() && (cachedArtifact == null || cachedArtifact.componentHashes != cacheHashes || cachedArtifact.signerHashes != signerHashes || cachedArtifact.appName != appName)) {
            artifactCache[packageInfo.packageName] = CachedAppArtifact(
                packageName = packageInfo.packageName,
                appName = appName,
                metadataFingerprint = metadataFingerprint,
                componentHashes = cacheHashes,
                signerHashes = signerHashes,
                lastSeenAt = System.currentTimeMillis()
            )
            artifactCacheDirty = true
        } else if (cachedArtifact != null) {
            artifactCache[packageInfo.packageName] = cachedArtifact.copy(lastSeenAt = System.currentTimeMillis())
            artifactCacheDirty = true
        }
        val fileThreat = componentHashes.asSequence()
            .mapNotNull { (_, hash) -> database.find(hash) }
            .firstOrNull { it.classification == ScanClassification.KNOWN_THREAT }
        val signerThreat = signerHashes.asSequence()
            .mapNotNull { database.findApk(ApkIndicatorKind.SIGNER, it) }
            .firstOrNull { it.classification == ApkIdentityClassification.KNOWN_THREAT }
        val packageHash = sha256Text(packageInfo.packageName)
        val packageThreat = database.findApk(ApkIndicatorKind.PACKAGE, packageHash)?.takeIf { it.classification == ApkIdentityClassification.KNOWN_THREAT }
        val legacyThreatReference = fileThreat?.id ?: signerThreat?.id ?: packageThreat?.id

        val basic = AppRiskEvaluator.evaluate(AppRiskInput(requestedPermissions, hasAccessibilityService, source, legacyThreatReference, packageInfo.services.orEmpty().toList()))
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
        val signerReputations = signerHashes.mapNotNull { database.findReputation(ReputationKind.SIGNER, it) }
        val packageReputation = database.findReputation(ReputationKind.PACKAGE, packageHash)
        val fileReputations = componentHashes.mapNotNull { (_, hash) -> database.findReputation(ReputationKind.FILE, hash) }
        signerReputations.mapNotNull { it.toFinding() }.forEach(findings::add)
        packageReputation?.toFinding()?.let(findings::add)
        fileReputations.mapNotNull { it.toFinding() }.forEach(findings::add)
        val impersonationFindings = ImpersonationDetector.evaluate(
            packageInfo.packageName,
            appName,
            database.detectionRuleset.brands,
            signerSha256s = signerHashes,
            isSideloaded = source == AppInstallSource.LOCAL_FILE || source == AppInstallSource.DOWNLOADED_FILE
        )
        findings += impersonationFindings
        val installedReasoning = LocalReasoningClassifier(database.detectionRuleset.reasoningWeights).reason(
            buildInstalledReasoningVector(basic.signals)
        )
        // Permission/capability reasoning for an installed app is a review signal, not proof of
        // malware. Official apps and Android components legitimately use camera, microphone,
        // storage, contacts, overlay, boot, or package-query capabilities. Exact file/signer/
        // package reputation matches are handled independently above and remain confirmed.
        installedReasoning.finding?.let { finding ->
            findings += finding.copy(
                id = "INSTALLED_APP_REASONING_REVIEW",
                score = minOf(finding.score, 10),
                confidence = FindingConfidence.MEDIUM,
                family = ThreatFamily.RISKWARE,
                reference = "INSTALLED_APP_REASONING_REVIEW"
            )
        }
        if (impersonationFindings.isNotEmpty() && AppRiskSignal.NON_STORE_INSTALL in basic.signals) {
            findings += DetectionFinding(
                "IMPERSONATION_SIDELOAD",
                DetectionSource.IMPERSONATION,
                20,
                FindingConfidence.MEDIUM,
                ThreatFamily.PHISHING
            )
        }
        val trustedAllowlist = signerReputations.any { it.disposition == ReputationDisposition.SAFE } ||
            fileReputations.any { it.disposition == ReputationDisposition.SAFE }

        // Analyze every APK component, not only the base APK. Split APKs can carry
        // additional dex, native code, URLs, or suspicious manifest capabilities.
        // The component hash/reputation checks above remain independent and cheap.
        val deepAnalyses = if (deep) {
            ApkComponentAnalysisPolicy
                .selectForDeepAnalysis(componentHashes)
                .mapNotNull { (file, hash) ->
                    deepAnalyzer.analyzeInstalledFile(file, hash)
                        .takeIf { it.state == ApkAnalysisState.VALID }
                }
        } else {
            emptyList()
        }
        findings += ApkComponentAnalysisPolicy.mergeFindings(deepAnalyses)
        findings += ThreatGraphEngine.correlate(findings, database.detectionRuleset.graphLinks)
        val verdict = VerdictEngine.evaluate(findings, allowlisted = trustedAllowlist)

        // Malware detection and privacy/capability review are deliberately separate. Camera,
        // microphone, contacts, boot, overlay, etc. belong in Permissions Control; they do not
        // increase the antivirus verdict shown on the Scan page. The installed-app malware score
        // is therefore the multi-engine verdict only.
        val finalScore = verdict.score.coerceIn(0, 100)
        val finalLevel = InstalledAppVerdictPolicy.riskLevel(verdict.level)
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
            deepAnalysisPerformed = deepAnalyses.isNotEmpty(),
            reasoningProbability = installedReasoning.probability
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

    private fun hashComponents(apkFiles: List<File>): List<Pair<File, String>> = apkFiles.mapNotNull { file ->
        runCatching { hashFile(file) }.getOrNull()?.let { hash -> file to hash }
    }

    /** Reasoning vector for installed apps is derived from the collected risk signals. */
    private fun buildInstalledReasoningVector(signals: Set<AppRiskSignal>): Map<String, Double> = mapOf(
        "surveillance" to bool(
            AppRiskSignal.ACCESSIBILITY_SERVICE in signals ||
                AppRiskSignal.OVERLAY in signals ||
                AppRiskSignal.INPUT_METHOD_SERVICE in signals ||
                AppRiskSignal.AUDIO_RECORDING_SERVICE in signals
        ),
        "stealth" to bool(false),
        "exfiltration" to bool(
            AppRiskSignal.SMS_ACCESS in signals ||
                AppRiskSignal.CONTACTS_ACCESS in signals ||
                AppRiskSignal.CALL_LOG_ACCESS in signals ||
                AppRiskSignal.PRECISE_LOCATION in signals ||
                AppRiskSignal.READ_MEDIA_ACCESS in signals ||
                AppRiskSignal.STORAGE_PERMISSION in signals
        ),
        "persistence" to bool(AppRiskSignal.BOOT_START in signals),
        "monetization" to bool(AppRiskSignal.SMS_ACCESS in signals),
        "privilege" to bool(
            AppRiskSignal.INSTALL_PACKAGES in signals || AppRiskSignal.QUERY_ALL_PACKAGES in signals
        ),
        "anti_analysis" to bool(false),
        "impersonation" to bool(false)
    )

    private fun bool(value: Boolean): Double = if (value) 1.0 else 0.0

    private fun appMetadataFingerprint(packageInfo: PackageInfo, apkFiles: List<File>): String {
        val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) packageInfo.longVersionCode else {
            @Suppress("DEPRECATION") packageInfo.versionCode.toLong()
        }
        val fileMetadata = apkFiles.joinToString(";") { file ->
            "${file.absolutePath}:${runCatching { file.length() }.getOrDefault(-1L)}:${runCatching { file.lastModified() }.getOrDefault(-1L)}"
        }
        return "${database.info.serial}|$versionCode|${packageInfo.lastUpdateTime}|$fileMetadata"
    }

    private fun flushArtifactCache() {
        if (!artifactCacheDirty) return
        artifactCacheStore.saveApps(artifactCache)
        artifactCacheDirty = false
    }

    private fun hashFile(file: File): String = FileInputStream(file).use { Sha256.fromStream(it) }
    private fun sha256Text(value: String): String = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    private fun signingCertificateSha256s(packageInfo: PackageInfo): Set<String> {
        val signerBytes: List<ByteArray> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = packageInfo.signingInfo ?: return emptySet()
            val signers = if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }
            signers.map { it.toByteArray() }
        } else {
            @Suppress("DEPRECATION") packageInfo.signatures.orEmpty().map { it.toByteArray() }
        }
        return signerBytes.mapTo(linkedSetOf()) { bytes ->
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        }
    }
}

