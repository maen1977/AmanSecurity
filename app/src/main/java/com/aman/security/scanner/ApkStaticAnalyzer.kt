package com.aman.security.scanner

import android.Manifest
import android.content.ContentResolver
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import com.aman.security.detection.CloudReputationClient
import com.aman.security.detection.DetectionFinding
import com.aman.security.detection.DetectionSource
import com.aman.security.detection.DetectionVerdictLevel
import com.aman.security.detection.FindingConfidence
import com.aman.security.detection.ImpersonationDetector
import com.aman.security.detection.LocalMalwareModel
import com.aman.security.detection.NetworkIndicatorExtractor
import com.aman.security.detection.ReputationDisposition
import com.aman.security.detection.ReputationKind
import com.aman.security.detection.SignatureRuleEngine
import com.aman.security.detection.StaticBehaviorEngine
import com.aman.security.detection.ThreatFamily
import com.aman.security.detection.ThreatGraphEngine
import com.aman.security.detection.VerdictEngine
import com.aman.security.detection.ZeroDayHeuristicEngine
import com.aman.security.detection.ZeroDayProfile
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipFile

class ApkStaticAnalyzer(
    private val context: Context,
    private val database: SignatureDatabase
) {
    private val resolver: ContentResolver = context.contentResolver
    private val packageManager: PackageManager = context.packageManager

    fun analyze(uri: Uri, expectedSha256: String): ApkStaticAnalysis {
        val directory = File(context.cacheDir, "apk-analysis").apply { mkdirs() }
        val temp = File(directory, "${UUID.randomUUID()}.apk")
        return try {
            val copiedHash = copyBounded(uri, temp) ?: return ApkStaticAnalysis(ApkAnalysisState.FAILED)
            if (!copiedHash.equals(expectedSha256, ignoreCase = true)) return ApkStaticAnalysis(ApkAnalysisState.SOURCE_CHANGED)
            analyzeFile(temp, copiedHash, allowCloudLookup = true)
        } catch (_: SizeLimitExceeded) {
            ApkStaticAnalysis(ApkAnalysisState.LIMIT_EXCEEDED)
        } catch (_: Exception) {
            ApkStaticAnalysis(ApkAnalysisState.FAILED)
        } finally {
            temp.delete()
        }
    }

    fun analyzeInstalledFile(file: File, expectedSha256: String): ApkStaticAnalysis {
        return try {
            if (!file.isFile || file.length() > MAX_APK_BYTES) return ApkStaticAnalysis(ApkAnalysisState.LIMIT_EXCEEDED)
            val actual = FileInputStream(file).use(Sha256::fromStream)
            if (!actual.equals(expectedSha256, ignoreCase = true)) return ApkStaticAnalysis(ApkAnalysisState.SOURCE_CHANGED)
            analyzeFile(file, actual, allowCloudLookup = false)
        } catch (_: SizeLimitExceeded) {
            ApkStaticAnalysis(ApkAnalysisState.LIMIT_EXCEEDED)
        } catch (_: Exception) {
            ApkStaticAnalysis(ApkAnalysisState.FAILED)
        }
    }

    private fun analyzeFile(file: File, fileSha256: String, allowCloudLookup: Boolean): ApkStaticAnalysis {
        val archive = try {
            inspectArchive(file)
        } catch (_: java.util.zip.ZipException) {
            return ApkStaticAnalysis(ApkAnalysisState.INVALID_APK)
        }
        val packageInfo = archivePackageInfo(file) ?: return ApkStaticAnalysis(ApkAnalysisState.INVALID_APK)
        val signals = linkedSetOf<ApkRiskSignal>()
        signals += manifestSignals(packageInfo)
        signals += archive.signals

        val markers = linkedSetOf<String>()
        markers += archive.markers
        if (ApkRiskSignal.BOOT_START in signals) markers += "BOOT_PERSISTENCE"
        if (ApkRiskSignal.ACCESSIBILITY_SERVICE in signals) markers += "ACCESSIBILITY_SERVICE"
        if (ApkRiskSignal.OVERLAY_PERMISSION in signals) markers += "OVERLAY_PERMISSION"
        if (ApkRiskSignal.REQUEST_INSTALL_PACKAGES in signals) markers += "INSTALL_PACKAGES"
        if (ApkRiskSignal.SMS_ACCESS in signals) markers += "SMS_ACCESS"
        if (ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE in signals) markers += "NOTIFICATION_LISTENER"
        if (ApkRiskSignal.MICROPHONE in signals) markers += "MICROPHONE_ACCESS"
        if (ApkRiskSignal.PRECISE_LOCATION in signals) markers += "LOCATION_ACCESS"
        if (ApkRiskSignal.CONTACTS_ACCESS in signals) markers += "CONTACTS_ACCESS"
        if (ApkRiskSignal.CALL_LOG_ACCESS in signals) markers += "CALL_LOG_ACCESS"
        if (ApkRiskSignal.DEVICE_ADMIN_RECEIVER in signals) markers += "DEVICE_ADMIN"

        val certificateHash = signingCertificateSha256(packageInfo)
        val signerIndicator = certificateHash?.let { database.findApk(ApkIndicatorKind.SIGNER, it) }
        val packageHash = packageInfo.packageName.takeIf { it.isNotBlank() }?.let(::sha256Text)
        val packageIndicator = packageHash?.let { database.findApk(ApkIndicatorKind.PACKAGE, it) }
        val identityIndicator = selectIdentityIndicator(signerIndicator, packageIndicator)

        val basicEvaluation = ApkRiskEvaluator.evaluate(signals)
        val findings = mutableListOf<DetectionFinding>()
        val ruleset = database.detectionRuleset

        database.find(fileSha256)?.let { signature ->
            findings += DetectionFinding(
                id = signature.id,
                source = DetectionSource.FILE_HASH,
                score = if (signature.classification == ScanClassification.TEST_SIGNATURE) 0 else 100,
                confidence = FindingConfidence.CONFIRMED,
                family = if (signature.classification == ScanClassification.TEST_SIGNATURE) {
                    ThreatFamily.TEST
                } else {
                    ruleset.findMetadata(signature.id)?.family?.takeUnless { it == ThreatFamily.UNKNOWN || it == ThreatFamily.TEST }
                        ?: ThreatFamily.MALWARE
                },
                reference = signature.id
            )
        }
        if (identityIndicator != null) {
            findings += DetectionFinding(
                id = identityIndicator.id,
                source = if (identityIndicator.kind == ApkIndicatorKind.SIGNER) DetectionSource.SIGNER_IDENTITY else DetectionSource.PACKAGE_IDENTITY,
                score = if (identityIndicator.classification == ApkIdentityClassification.TEST_SIGNATURE) 0 else 100,
                confidence = FindingConfidence.CONFIRMED,
                family = if (identityIndicator.classification == ApkIdentityClassification.TEST_SIGNATURE) {
                    ThreatFamily.TEST
                } else {
                    ruleset.findMetadata(identityIndicator.id)?.family?.takeUnless { it == ThreatFamily.UNKNOWN || it == ThreatFamily.TEST }
                        ?: ThreatFamily.MALWARE
                },
                reference = identityIndicator.id
            )
        }

        val ruleFindings = SignatureRuleEngine.match(markers, ruleset.rules)
        findings += ruleFindings
        findings += StaticBehaviorEngine.evaluate(signals, markers)
        findings += ZeroDayHeuristicEngine.evaluate(
            ZeroDayProfile(
                signals = signals,
                markers = markers,
                hiddenDexPayloadCount = archive.hiddenDexPayloadCount,
                hiddenElfPayloadCount = archive.hiddenElfPayloadCount,
                nestedArchivePayloadCount = archive.nestedArchivePayloadCount,
                highEntropyAssetCount = archive.highEntropyAssetCount,
                dexFileCount = archive.dexFileCount,
                nativeLibraryCount = archive.nativeLibraryCount,
                codeScanTruncated = archive.codeScanTruncated
            )
        )
        findings += ImpersonationDetector.evaluate(packageInfo.packageName, null, ruleset.brands, signerSha256 = certificateHash)

        val signerReputation = certificateHash?.let { database.findReputation(ReputationKind.SIGNER, it) }
        val packageReputation = packageHash?.let { database.findReputation(ReputationKind.PACKAGE, it) }
        val fileReputation = database.findReputation(ReputationKind.FILE, fileSha256)
        signerReputation?.toFinding()?.let(findings::add)
        packageReputation?.toFinding()?.let(findings::add)
        fileReputation?.toFinding()?.let(findings::add)
        if (database.find(fileSha256) == null && fileReputation == null && database.mightContainMaliciousFileHash(fileSha256)) {
            findings += DetectionFinding(
                "OFFLINE_BLOOM_REPUTATION_HIT",
                DetectionSource.REPUTATION,
                8,
                FindingConfidence.LOW,
                ThreatFamily.MALWARE
            )
        }
        // Only reviewed exact-file or signer SAFE reputation may suppress heuristics.
        // Package-name reputation alone is not sufficient because a malicious APK can reuse a package name.
        var trustedAllowlist = signerReputation?.disposition == ReputationDisposition.SAFE ||
            fileReputation?.disposition == ReputationDisposition.SAFE
        if (allowCloudLookup) {
            when (val cloud = CloudReputationClient(context).querySha256(fileSha256)) {
                is CloudReputationClient.Result.Known -> {
                    if (cloud.malicious) {
                        findings += DetectionFinding(
                            id = cloud.id,
                            source = DetectionSource.CLOUD_REPUTATION,
                            score = 100,
                            confidence = FindingConfidence.CONFIRMED,
                            family = cloud.family.takeUnless { it == ThreatFamily.UNKNOWN } ?: ThreatFamily.MALWARE,
                            reference = cloud.id
                        )
                    } else if (cloud.safe) {
                        // Only an exact full-hash SAFE record from a signed shard may suppress heuristics.
                        trustedAllowlist = true
                    }
                }
                else -> Unit
            }
        }

        val urlScanner = UrlScanner(database::findUrl)
        var knownNetworkMatches = 0
        archive.networkUrls.take(MAX_NETWORK_LOOKUPS).forEach { candidate ->
            val result = urlScanner.scan(candidate)
            if (result.riskLevel == UrlRiskLevel.KNOWN_MALICIOUS || result.riskLevel == UrlRiskLevel.KNOWN_PHISHING) {
                knownNetworkMatches += 1
                findings += DetectionFinding(
                    id = result.threatReference ?: "NETWORK_KNOWN_THREAT",
                    source = DetectionSource.NETWORK,
                    score = 100,
                    confidence = FindingConfidence.CONFIRMED,
                    family = if (result.riskLevel == UrlRiskLevel.KNOWN_PHISHING) ThreatFamily.PHISHING else ThreatFamily.MALWARE,
                    reference = result.threatReference
                )
            }
        }
        archive.networkDomains.take(MAX_NETWORK_LOOKUPS).forEach { host ->
            val result = urlScanner.scan("https://$host/")
            if (result.riskLevel == UrlRiskLevel.KNOWN_MALICIOUS || result.riskLevel == UrlRiskLevel.KNOWN_PHISHING) {
                knownNetworkMatches += 1
                findings += DetectionFinding(
                    id = result.threatReference ?: "NETWORK_HOST_THREAT",
                    source = DetectionSource.NETWORK,
                    score = 100,
                    confidence = FindingConfidence.CONFIRMED,
                    family = if (result.riskLevel == UrlRiskLevel.KNOWN_PHISHING) ThreatFamily.PHISHING else ThreatFamily.MALWARE,
                    reference = result.threatReference
                )
            }
        }
        archive.networkIps.take(MAX_NETWORK_LOOKUPS).forEach { ip ->
            val result = urlScanner.scan("https://$ip/")
            if (result.riskLevel == UrlRiskLevel.KNOWN_MALICIOUS || result.riskLevel == UrlRiskLevel.KNOWN_PHISHING) {
                knownNetworkMatches += 1
                findings += DetectionFinding(
                    id = result.threatReference ?: "NETWORK_IP_THREAT",
                    source = DetectionSource.NETWORK,
                    score = 100,
                    confidence = FindingConfidence.CONFIRMED,
                    family = if (result.riskLevel == UrlRiskLevel.KNOWN_PHISHING) ThreatFamily.PHISHING else ThreatFamily.MALWARE,
                    reference = result.threatReference
                )
            }
        }

        if ("PACKER_PRESENT" in markers) {
            findings += DetectionFinding("PACKER_PRESENT", DetectionSource.PACKER, 8, FindingConfidence.LOW, ThreatFamily.RISKWARE)
        }
        if ("HEAVY_REFLECTION" in markers && "DYNAMIC_CODE" in markers) {
            findings += DetectionFinding("OBFUSCATED_DYNAMIC_CODE", DetectionSource.PACKER, 16, FindingConfidence.MEDIUM, ThreatFamily.RISKWARE)
        }

        val modelFeatures = buildModelFeatures(signals, markers, archive, knownNetworkMatches)
        val modelResult = LocalMalwareModel(ruleset.modelWeights).infer(modelFeatures)
        modelResult.finding?.let(findings::add)
        findings += ThreatGraphEngine.correlate(findings, ruleset.graphLinks)

        val verdict = VerdictEngine.evaluate(findings, allowlisted = trustedAllowlist)
        val combinedScore = maxOf(basicEvaluation.score, verdict.score)
        val combinedLevel = when {
            verdict.level in setOf(
                DetectionVerdictLevel.KNOWN_THREAT,
                DetectionVerdictLevel.VERY_HIGH,
                DetectionVerdictLevel.HIGH
            ) || combinedScore >= 55 -> ApkRiskLevel.HIGH
            combinedScore >= 20 -> ApkRiskLevel.REVIEW
            else -> ApkRiskLevel.LOW
        }
        val components = (packageInfo.activities?.size ?: 0) + (packageInfo.services?.size ?: 0) +
            (packageInfo.receivers?.size ?: 0) + (packageInfo.providers?.size ?: 0)

        return ApkStaticAnalysis(
            state = ApkAnalysisState.VALID,
            riskScore = combinedScore.coerceAtMost(100),
            riskLevel = combinedLevel,
            signals = signals,
            requestedPermissionCount = packageInfo.requestedPermissions?.size ?: 0,
            componentCount = components,
            dexFileCount = archive.dexFileCount,
            nativeLibraryCount = archive.nativeLibraryCount,
            signingCertificateSha256 = certificateHash,
            identityIndicator = identityIndicator,
            codeScanTruncated = archive.codeScanTruncated,
            advancedVerdict = verdict,
            networkIndicatorCount = archive.networkUrls.size + archive.networkDomains.size + archive.networkIps.size,
            matchedRuleCount = ruleFindings.size,
            markerCount = markers.size,
            localModelProbability = modelResult.probability,
            hiddenPayloadCount = archive.hiddenDexPayloadCount + archive.hiddenElfPayloadCount + archive.nestedArchivePayloadCount,
            antiAnalysisMarkerCount = listOf("ANTI_DEBUG", "EMULATOR_CHECK", "ENVIRONMENT_FINGERPRINT").count(markers::contains)
        )
    }

    private fun com.aman.security.detection.ReputationIndicator.toFinding(): DetectionFinding? {
        return when (disposition) {
            ReputationDisposition.SAFE -> null
            ReputationDisposition.TEST -> DetectionFinding(id, DetectionSource.REPUTATION, 0, FindingConfidence.CONFIRMED, ThreatFamily.TEST, id)
            ReputationDisposition.MALICIOUS -> DetectionFinding(id, DetectionSource.REPUTATION, 100, confidence, family, id)
        }
    }

    private fun buildModelFeatures(
        signals: Set<ApkRiskSignal>,
        markers: Set<String>,
        archive: ArchiveSignals,
        knownNetworkMatches: Int
    ): Map<String, Double> = buildMap {
        put("ACCESSIBILITY", bool(ApkRiskSignal.ACCESSIBILITY_SERVICE in signals))
        put("OVERLAY", bool(ApkRiskSignal.OVERLAY_PERMISSION in signals))
        put("SMS", bool(ApkRiskSignal.SMS_ACCESS in signals))
        put("BOOT", bool(ApkRiskSignal.BOOT_START in signals))
        put("INSTALL_PACKAGES", bool(ApkRiskSignal.REQUEST_INSTALL_PACKAGES in signals))
        put("DYNAMIC_CODE", bool("DYNAMIC_CODE" in markers))
        put("COMMAND_EXEC", bool("COMMAND_EXEC" in markers))
        put("NETWORK_CLIENT", bool("NETWORK_CLIENT" in markers))
        put("PACKER", bool("PACKER_PRESENT" in markers))
        put("REFLECTION", bool("HEAVY_REFLECTION" in markers))
        put("SCREEN_CAPTURE", bool("SCREEN_CAPTURE" in markers))
        put("CLIPBOARD", bool("CLIPBOARD_READ" in markers))
        put("NATIVE_CODE", bool(archive.nativeLibraryCount > 0))
        put("MANY_DEX", bool(archive.dexFileCount >= MANY_DEX_THRESHOLD))
        put("KNOWN_NETWORK", bool(knownNetworkMatches > 0))
        put("HIDDEN_PAYLOAD", bool(archive.hiddenDexPayloadCount + archive.hiddenElfPayloadCount > 0))
        put("ANTI_ANALYSIS", bool("ANTI_DEBUG" in markers && "EMULATOR_CHECK" in markers))
        put("ENCRYPTED_ASSET", bool(archive.highEntropyAssetCount >= 2))
    }

    private fun bool(value: Boolean): Double = if (value) 1.0 else 0.0

    private fun archivePackageInfo(file: File): PackageInfo? {
        val signingFlag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or signingFlag
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageArchiveInfo(file.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageArchiveInfo(file.absolutePath, flags)
        }
    }

    private fun manifestSignals(packageInfo: PackageInfo): Set<ApkRiskSignal> {
        val signals = linkedSetOf<ApkRiskSignal>()
        val permissions = packageInfo.requestedPermissions?.toSet().orEmpty()
        if (Manifest.permission.SYSTEM_ALERT_WINDOW in permissions) signals += ApkRiskSignal.OVERLAY_PERMISSION
        if (Manifest.permission.REQUEST_INSTALL_PACKAGES in permissions) signals += ApkRiskSignal.REQUEST_INSTALL_PACKAGES
        if (permissions.any { it in SMS_PERMISSIONS }) signals += ApkRiskSignal.SMS_ACCESS
        if (Manifest.permission.READ_CONTACTS in permissions) signals += ApkRiskSignal.CONTACTS_ACCESS
        if (permissions.any { it in CALL_LOG_PERMISSIONS }) signals += ApkRiskSignal.CALL_LOG_ACCESS
        if (Manifest.permission.RECORD_AUDIO in permissions) signals += ApkRiskSignal.MICROPHONE
        if (Manifest.permission.CAMERA in permissions) signals += ApkRiskSignal.CAMERA
        if (Manifest.permission.ACCESS_FINE_LOCATION in permissions) signals += ApkRiskSignal.PRECISE_LOCATION
        if (Manifest.permission.RECEIVE_BOOT_COMPLETED in permissions) signals += ApkRiskSignal.BOOT_START
        if (Manifest.permission.QUERY_ALL_PACKAGES in permissions) signals += ApkRiskSignal.QUERY_ALL_PACKAGES
        if (packageInfo.services?.any { it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE } == true) signals += ApkRiskSignal.ACCESSIBILITY_SERVICE
        if (packageInfo.services?.any { it.permission == Manifest.permission.BIND_NOTIFICATION_LISTENER_SERVICE } == true) signals += ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE
        if (packageInfo.services?.any { it.permission == Manifest.permission.BIND_VPN_SERVICE } == true) signals += ApkRiskSignal.VPN_SERVICE
        if (packageInfo.receivers?.any { it.permission == Manifest.permission.BIND_DEVICE_ADMIN } == true) signals += ApkRiskSignal.DEVICE_ADMIN_RECEIVER
        val flags = packageInfo.applicationInfo?.flags ?: 0
        if (flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) signals += ApkRiskSignal.DEBUGGABLE
        return signals
    }

    private fun inspectArchive(file: File): ArchiveSignals {
        ZipFile(file).use { zip ->
            var entryCount = 0
            var declaredUncompressed = 0L
            var nativeCount = 0
            val dexEntries = mutableListOf<java.util.zip.ZipEntry>()
            val markers = linkedSetOf<String>()
            val networkUrls = linkedSetOf<String>()
            val networkDomains = linkedSetOf<String>()
            val networkIps = linkedSetOf<String>()
            var hiddenDexPayloadCount = 0
            var hiddenElfPayloadCount = 0
            var nestedArchivePayloadCount = 0
            var highEntropyAssetCount = 0
            var payloadSampleBudget = MAX_ASSET_SAMPLE_TOTAL_BYTES
            var payloadCandidates = 0
            val enumeration = zip.entries()
            while (enumeration.hasMoreElements()) {
                val entry = enumeration.nextElement()
                entryCount += 1
                if (entryCount > MAX_ZIP_ENTRIES) throw SizeLimitExceeded()
                if (entry.size > 0) {
                    declaredUncompressed += entry.size
                    if (declaredUncompressed > MAX_DECLARED_UNCOMPRESSED_BYTES) throw SizeLimitExceeded()
                }
                val name = entry.name
                if (DEX_NAME.matches(name.substringAfterLast('/'))) dexEntries += entry
                if (name.startsWith("lib/") && name.endsWith(".so")) nativeCount += 1
                val lower = name.lowercase()
                if (PACKER_ENTRY_MARKERS.any(lower::contains)) markers += "PACKER_PRESENT"
                if (lower.endsWith(".dex") && !DEX_NAME.matches(name.substringAfterLast('/'))) markers += "SECONDARY_DEX_PAYLOAD"

                if (!entry.isDirectory && isPayloadCandidate(lower) && payloadCandidates < MAX_ASSET_CANDIDATES && payloadSampleBudget > 0L) {
                    payloadCandidates += 1
                    val allowed = minOf(MAX_ASSET_SAMPLE_BYTES, payloadSampleBudget)
                    val sample = zip.getInputStream(entry).use { readBoundedSample(it, allowed) }
                    payloadSampleBudget -= sample.size
                    if (sample.startsWithMagic(DEX_MAGIC)) {
                        hiddenDexPayloadCount += 1
                        markers += "HIDDEN_DEX_PAYLOAD"
                    } else if (sample.startsWithMagic(ELF_MAGIC)) {
                        hiddenElfPayloadCount += 1
                        markers += "HIDDEN_ELF_PAYLOAD"
                    } else if (sample.startsWithMagic(ZIP_MAGIC)) {
                        nestedArchivePayloadCount += 1
                        markers += "NESTED_ARCHIVE_PAYLOAD"
                    }
                    if (sample.size >= MIN_ENTROPY_SAMPLE_BYTES && shannonEntropy(sample) >= HIGH_ENTROPY_THRESHOLD) {
                        highEntropyAssetCount += 1
                        markers += "HIGH_ENTROPY_ASSET"
                    }
                }
            }
            val signals = linkedSetOf<ApkRiskSignal>()
            if (nativeCount > 0) signals += ApkRiskSignal.NATIVE_CODE
            if (dexEntries.size >= MANY_DEX_THRESHOLD) signals += ApkRiskSignal.MANY_DEX_FILES

            var remainingCodeBytes = MAX_DEX_SCAN_BYTES
            var truncated = false
            for (entry in dexEntries) {
                if (remainingCodeBytes <= 0L) { truncated = true; break }
                val scan = zip.getInputStream(entry).use { input -> scanDex(input, remainingCodeBytes) }
                remainingCodeBytes -= scan.bytesRead
                signals += scan.signals
                markers += scan.markers
                networkUrls += scan.urls
                networkDomains += scan.domains
                networkIps += scan.ips
                if (scan.truncated) { truncated = true; break }
            }
            return ArchiveSignals(
                dexEntries.size, nativeCount, signals, markers, networkUrls, networkDomains, networkIps, truncated,
                hiddenDexPayloadCount, hiddenElfPayloadCount, nestedArchivePayloadCount, highEntropyAssetCount
            )
        }
    }

    private fun scanDex(input: InputStream, maxBytes: Long): DexScan {
        val targets = CODE_MARKERS.keys.associateWith { it.toByteArray(Charsets.US_ASCII) }
        val signals = linkedSetOf<ApkRiskSignal>()
        val markers = linkedSetOf<String>()
        val urls = linkedSetOf<String>()
        val domains = linkedSetOf<String>()
        val ips = linkedSetOf<String>()
        val maxNeedle = targets.values.maxOf { it.size }
        val buffer = ByteArray(32 * 1024)
        var carry = ByteArray(0)
        var total = 0L
        var truncated = false

        while (total < maxBytes) {
            val allowed = minOf(buffer.size.toLong(), maxBytes - total).toInt()
            val read = input.read(buffer, 0, allowed)
            if (read < 0) break
            total += read
            val combined = ByteArray(carry.size + read)
            carry.copyInto(combined, 0)
            buffer.copyInto(combined, carry.size, 0, read)

            CODE_MARKERS.forEach { (text, effect) ->
                if (containsBytes(combined, targets.getValue(text))) {
                    effect.signal?.let(signals::add)
                    markers += effect.marker
                }
            }
            val ascii = combined.toString(Charsets.ISO_8859_1)
            val network = NetworkIndicatorExtractor.extract(ascii, MAX_NETWORK_INDICATORS)
            if (urls.size < MAX_NETWORK_INDICATORS) urls += network.urls.take(MAX_NETWORK_INDICATORS - urls.size)
            if (domains.size < MAX_NETWORK_INDICATORS) domains += network.domains.take(MAX_NETWORK_INDICATORS - domains.size)
            if (ips.size < MAX_NETWORK_INDICATORS) ips += network.ips.take(MAX_NETWORK_INDICATORS - ips.size)

            val keep = minOf(maxNeedle - 1, combined.size)
            carry = combined.copyOfRange(combined.size - keep, combined.size)
        }
        if (total >= maxBytes && input.read() >= 0) truncated = true
        return DexScan(total, signals, markers, urls, domains, ips, truncated)
    }


    private fun isPayloadCandidate(lowerName: String): Boolean {
        if (lowerName.startsWith("lib/") || lowerName.endsWith(".so")) return false
        if (DEX_NAME.matches(lowerName.substringAfterLast('/'))) return false
        return lowerName.startsWith("assets/") || lowerName.startsWith("res/raw/") ||
            PAYLOAD_EXTENSIONS.any(lowerName::endsWith)
    }

    private fun readBoundedSample(input: InputStream, maxBytes: Long): ByteArray {
        val output = java.io.ByteArrayOutputStream(minOf(maxBytes, 256L * 1024L).toInt())
        val buffer = ByteArray(16 * 1024)
        var remaining = maxBytes
        while (remaining > 0) {
            val read = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (read < 0) break
            output.write(buffer, 0, read)
            remaining -= read
        }
        return output.toByteArray()
    }

    private fun ByteArray.startsWithMagic(magic: ByteArray): Boolean {
        if (size < magic.size) return false
        return magic.indices.all { this[it] == magic[it] }
    }

    private fun shannonEntropy(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0
        val counts = IntArray(256)
        data.forEach { counts[it.toInt() and 0xff]++ }
        val size = data.size.toDouble()
        var entropy = 0.0
        counts.filter { it > 0 }.forEach { count ->
            val p = count / size
            entropy -= p * (kotlin.math.ln(p) / kotlin.math.ln(2.0))
        }
        return entropy
    }

    private fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }

    private fun copyBounded(uri: Uri, destination: File): String? {
        val digest = MessageDigest.getInstance("SHA-256")
        val input = resolver.openInputStream(uri) ?: return null
        input.use { source ->
            FileOutputStream(destination).use { output ->
                val buffer = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val read = source.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > MAX_APK_BYTES) throw SizeLimitExceeded()
                    digest.update(buffer, 0, read)
                    output.write(buffer, 0, read)
                }
                output.fd.sync()
            }
        }
        return digest.digest().toHex()
    }

    private fun signingCertificateSha256(packageInfo: PackageInfo): String? {
        val signer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = packageInfo.signingInfo ?: return null
            val signers = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
            signers.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION") packageInfo.signatures?.firstOrNull()?.toByteArray()
        } ?: return null
        return MessageDigest.getInstance("SHA-256").digest(signer).toHex()
    }

    private fun selectIdentityIndicator(signer: ApkIdentityIndicator?, packageName: ApkIdentityIndicator?): ApkIdentityIndicator? {
        val values = listOfNotNull(signer, packageName)
        return values.firstOrNull { it.classification == ApkIdentityClassification.KNOWN_THREAT } ?: values.firstOrNull()
    }

    private fun sha256Text(value: String): String = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).toHex()
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private data class MarkerEffect(val marker: String, val signal: ApkRiskSignal? = null)
    private data class ArchiveSignals(
        val dexFileCount: Int,
        val nativeLibraryCount: Int,
        val signals: Set<ApkRiskSignal>,
        val markers: Set<String>,
        val networkUrls: Set<String>,
        val networkDomains: Set<String>,
        val networkIps: Set<String>,
        val codeScanTruncated: Boolean,
        val hiddenDexPayloadCount: Int,
        val hiddenElfPayloadCount: Int,
        val nestedArchivePayloadCount: Int,
        val highEntropyAssetCount: Int
    )
    private data class DexScan(
        val bytesRead: Long,
        val signals: Set<ApkRiskSignal>,
        val markers: Set<String>,
        val urls: Set<String>,
        val domains: Set<String>,
        val ips: Set<String>,
        val truncated: Boolean
    )
    private class SizeLimitExceeded : Exception()

    companion object {
        private const val MAX_APK_BYTES = 512L * 1024L * 1024L
        private const val MAX_DECLARED_UNCOMPRESSED_BYTES = 2L * 1024L * 1024L * 1024L
        private const val MAX_ZIP_ENTRIES = 20_000
        private const val MAX_DEX_SCAN_BYTES = 64L * 1024L * 1024L
        private const val MAX_NETWORK_INDICATORS = 64
        private const val MAX_NETWORK_LOOKUPS = 32
        private const val MAX_ASSET_CANDIDATES = 64
        private const val MAX_ASSET_SAMPLE_BYTES = 256L * 1024L
        private const val MAX_ASSET_SAMPLE_TOTAL_BYTES = 4L * 1024L * 1024L
        private const val MIN_ENTROPY_SAMPLE_BYTES = 32 * 1024
        private const val HIGH_ENTROPY_THRESHOLD = 7.75
        private const val MANY_DEX_THRESHOLD = 8
        private val DEX_NAME = Regex("classes(?:[0-9]+)?\\.dex", RegexOption.IGNORE_CASE)
        private val SMS_PERMISSIONS = setOf(Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS, Manifest.permission.SEND_SMS)
        private val CALL_LOG_PERMISSIONS = setOf(Manifest.permission.READ_CALL_LOG, Manifest.permission.WRITE_CALL_LOG)
        private val PACKER_ENTRY_MARKERS = setOf("libjiagu", "libsecexe", "libsecmain", "bangcle", "secneo", "ijiami", "dexhelper")
        private val PAYLOAD_EXTENSIONS = setOf(".dat", ".bin", ".blob", ".enc", ".pak", ".payload")
        private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0a)
        private val ELF_MAGIC = byteArrayOf(0x7f, 0x45, 0x4c, 0x46)
        private val ZIP_MAGIC = byteArrayOf(0x50, 0x4b, 0x03, 0x04)
        private val CODE_MARKERS = linkedMapOf(
            "Ldalvik/system/DexClassLoader;" to MarkerEffect("DYNAMIC_CODE", ApkRiskSignal.DYNAMIC_CODE_LOADING),
            "Ldalvik/system/InMemoryDexClassLoader;" to MarkerEffect("DYNAMIC_CODE", ApkRiskSignal.DYNAMIC_CODE_LOADING),
            "Ljava/lang/Runtime;" to MarkerEffect("COMMAND_EXEC", ApkRiskSignal.RUNTIME_EXECUTION),
            "Ljava/lang/ProcessBuilder;" to MarkerEffect("COMMAND_EXEC", ApkRiskSignal.RUNTIME_EXECUTION),
            "Landroid/telephony/SmsManager;" to MarkerEffect("SMS_API", ApkRiskSignal.SMS_API),
            "getDeviceId" to MarkerEffect("DEVICE_ID", ApkRiskSignal.DEVICE_IDENTIFIER_API),
            "Landroid/media/projection/MediaProjection;" to MarkerEffect("SCREEN_CAPTURE"),
            "Landroid/content/ClipboardManager;" to MarkerEffect("CLIPBOARD_READ"),
            "performGlobalAction" to MarkerEffect("ACCESSIBILITY_ACTIONS"),
            "dispatchGesture" to MarkerEffect("ACCESSIBILITY_ACTIONS"),
            "Ljava/net/HttpURLConnection;" to MarkerEffect("NETWORK_CLIENT"),
            "Lokhttp3/" to MarkerEffect("NETWORK_CLIENT"),
            "Ljava/net/Socket;" to MarkerEffect("NETWORK_CLIENT"),
            "Landroid/app/DownloadManager;" to MarkerEffect("DOWNLOADER"),
            "Landroid/content/pm/PackageInstaller;" to MarkerEffect("INSTALLER_API"),
            "Ljava/lang/reflect/Method;" to MarkerEffect("HEAVY_REFLECTION"),
            "forName" to MarkerEffect("HEAVY_REFLECTION"),
            "setComponentEnabledSetting" to MarkerEffect("HIDE_COMPONENT"),
            "Ljavax/crypto/Cipher;" to MarkerEffect("FILE_ENCRYPTION"),
            "listFiles" to MarkerEffect("MASS_FILE_ACCESS"),
            "Ljava/lang/System;->loadLibrary" to MarkerEffect("NATIVE_LOAD"),
            "Landroid/provider/ContactsContract;" to MarkerEffect("CONTACTS_API"),
            "Landroid/provider/CallLog;" to MarkerEffect("CALL_LOG_API"),
            "Landroid/location/LocationManager;" to MarkerEffect("LOCATION_API"),
            "Landroid/media/MediaRecorder;" to MarkerEffect("AUDIO_RECORDING"),
            "Landroid/view/accessibility/AccessibilityNodeInfo;" to MarkerEffect("ACCESSIBILITY_NODE"),
            "addJavascriptInterface" to MarkerEffect("WEBVIEW_BRIDGE"),
            "getInstalledPackages" to MarkerEffect("APP_ENUMERATION"),
            "getInstalledApplications" to MarkerEffect("APP_ENUMERATION"),
            "Landroid/app/admin/DevicePolicyManager;" to MarkerEffect("DEVICE_POLICY"),
            "Landroid/accounts/AccountManager;" to MarkerEffect("ACCOUNT_ACCESS"),
            "Landroid/os/Debug;->isDebuggerConnected" to MarkerEffect("ANTI_DEBUG"),
            "/proc/self/status" to MarkerEffect("ANTI_DEBUG"),
            "ro.kernel.qemu" to MarkerEffect("EMULATOR_CHECK"),
            "goldfish" to MarkerEffect("EMULATOR_CHECK"),
            "Landroid/os/Build;->FINGERPRINT" to MarkerEffect("ENVIRONMENT_FINGERPRINT"),
            "Ljava/lang/System;->load" to MarkerEffect("NATIVE_LOAD"),
            "com.stub.StubApp" to MarkerEffect("PACKER_PRESENT"),
            "com.secneo" to MarkerEffect("PACKER_PRESENT"),
            "com.bangcle" to MarkerEffect("PACKER_PRESENT")
        )
    }
}
