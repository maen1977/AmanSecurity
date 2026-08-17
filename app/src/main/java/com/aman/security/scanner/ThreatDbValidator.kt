package com.aman.security.scanner

import com.aman.security.detection.DetectionRule
import com.aman.security.detection.DetectionRuleset
import com.aman.security.detection.FindingConfidence
import com.aman.security.detection.ProtectedBrandProfile
import com.aman.security.detection.ReputationDisposition
import com.aman.security.detection.ReputationIndicator
import com.aman.security.detection.ReputationKind
import com.aman.security.detection.ThreatFamily
import com.aman.security.detection.ThreatIntelMetadata
import com.aman.security.detection.ThreatGraphLink
import com.aman.security.detection.ThreatGraphRelation

object ThreatDbValidator {
    data class ValidatedPackage(
        val manifest: ThreatDbManifest,
        val signatures: Map<String, ThreatSignature>,
        val urlIndicators: Map<String, UrlThreatIndicator>,
        val apkIdentityIndicators: Map<String, ApkIdentityIndicator>,
        val detectionRuleset: DetectionRuleset
    )

    fun validate(
        manifestBytes: ByteArray,
        databaseBytes: ByteArray,
        urlDatabaseBytes: ByteArray? = null,
        apkIdentityDatabaseBytes: ByteArray? = null,
        detectionDatabaseBytes: ByteArray? = null
    ): ValidatedPackage {
        require(manifestBytes.size <= 64 * 1024)
        require(databaseBytes.size <= 64 * 1024 * 1024)

        val manifest = ThreatDbManifest.parse(manifestBytes)
        require(manifest.minAppVersionCode <= com.aman.security.BuildConfig.VERSION_CODE)
        require(sha256(databaseBytes) == manifest.dbSha256)

        val parsed = databaseBytes.toString(Charsets.UTF_8)
            .lineSequence()
            .filter(::dataLine)
            .mapNotNull(::parseFileLine)
            .toList()
        require(parsed.size == manifest.entries)
        require(parsed.map { it.sha256 }.distinct().size == parsed.size)
        if (manifest.schema >= 4) require(ThreatDbCanary.valid(parsed)) { "Bundled threat DB canary missing or invalid" }

        val urls = if (manifest.schema >= 2) {
            val urlBytes = requireNotNull(urlDatabaseBytes)
            require(urlBytes.size <= 96 * 1024 * 1024)
            require(sha256(urlBytes) == manifest.urlDbSha256)
            val parsedUrls = urlBytes.toString(Charsets.UTF_8)
                .lineSequence().filter(::dataLine).mapNotNull(::parseUrlLine).toList()
            require(parsedUrls.size == manifest.urlEntries)
            require(parsedUrls.map { "${it.kind}:${it.sha256}" }.distinct().size == parsedUrls.size)
            parsedUrls
        } else emptyList()

        val apkIdentities = if (manifest.schema >= 3) {
            val apkBytes = requireNotNull(apkIdentityDatabaseBytes)
            require(apkBytes.size <= 64 * 1024 * 1024)
            require(sha256(apkBytes) == manifest.apkIdentityDbSha256)
            val parsedApk = apkBytes.toString(Charsets.UTF_8)
                .lineSequence().filter(::dataLine).mapNotNull(::parseApkIdentityLine).toList()
            require(parsedApk.size == manifest.apkIdentityEntries)
            require(parsedApk.map { "${it.kind}:${it.sha256}" }.distinct().size == parsedApk.size)
            parsedApk
        } else emptyList()

        val detectionRuleset = if (manifest.schema >= 4) {
            val bytes = requireNotNull(detectionDatabaseBytes)
            require(bytes.size <= 16 * 1024 * 1024)
            require(sha256(bytes) == manifest.detectionDbSha256)
            parseDetectionRules(bytes, manifest.detectionEntries)
        } else DetectionRuleset()

        return ValidatedPackage(
            manifest = manifest,
            signatures = parsed.associateBy { it.sha256 },
            urlIndicators = urls.associateBy { "${it.kind}:${it.sha256}" },
            apkIdentityIndicators = apkIdentities.associateBy { "${it.kind}:${it.sha256}" },
            detectionRuleset = detectionRuleset
        )
    }

    private fun sha256(bytes: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun dataLine(line: String): Boolean = line.isNotBlank() && !line.trimStart().startsWith("#")

    private fun parseFileLine(line: String): ThreatSignature? {
        val parts = line.split('|')
        if (parts.size != 3) return null
        val hash = parts[0].trim().lowercase()
        if (!hash.matches(Regex("^[a-f0-9]{64}$"))) return null
        val id = parts[1].trim()
        if (!id.matches(Regex("^[A-Z0-9_]{3,96}$"))) return null
        val classification = runCatching { ScanClassification.valueOf(parts[2].trim()) }.getOrNull() ?: return null
        if (classification == ScanClassification.NO_KNOWN_THREAT || classification == ScanClassification.UNKNOWN_APK) return null
        return ThreatSignature(hash, id, classification)
    }

    private fun parseUrlLine(line: String): UrlThreatIndicator? {
        val parts = line.split('|')
        if (parts.size != 4) return null
        val kind = runCatching { UrlIndicatorKind.valueOf(parts[0].trim()) }.getOrNull() ?: return null
        val hash = parts[1].trim().lowercase()
        if (!hash.matches(Regex("^[a-f0-9]{64}$"))) return null
        val id = parts[2].trim()
        if (!id.matches(Regex("^[A-Z0-9_]{3,96}$"))) return null
        val classification = runCatching { UrlThreatClassification.valueOf(parts[3].trim()) }.getOrNull() ?: return null
        return UrlThreatIndicator(kind, hash, id, classification)
    }

    private fun parseApkIdentityLine(line: String): ApkIdentityIndicator? {
        val parts = line.split('|')
        if (parts.size != 4) return null
        val kind = runCatching { ApkIndicatorKind.valueOf(parts[0].trim()) }.getOrNull() ?: return null
        val hash = parts[1].trim().lowercase()
        if (!hash.matches(Regex("^[a-f0-9]{64}$"))) return null
        val id = parts[2].trim()
        if (!id.matches(Regex("^[A-Z0-9_]{3,96}$"))) return null
        val classification = runCatching { ApkIdentityClassification.valueOf(parts[3].trim()) }.getOrNull() ?: return null
        return ApkIdentityIndicator(kind, hash, id, classification)
    }

    private fun parseDetectionRules(bytes: ByteArray, expectedCount: Int): DetectionRuleset {
        val rules = mutableListOf<DetectionRule>()
        val brands = mutableListOf<ProtectedBrandProfile>()
        val model = linkedMapOf<String, Double>()
        val reasoning = linkedMapOf<String, Double>()
        val reputation = linkedMapOf<String, ReputationIndicator>()
        val metadata = linkedMapOf<String, ThreatIntelMetadata>()
        val brandSigners = linkedMapOf<String, MutableSet<String>>()
        val graphLinks = mutableListOf<ThreatGraphLink>()
        var rows = 0
        bytes.toString(Charsets.UTF_8).lineSequence().filter(::dataLine).forEach { line ->
            rows += 1
            val p = line.split('|')
            when (p.firstOrNull()) {
                "RULE" -> {
                    require(p.size == 7)
                    val id = strictId(p[1])
                    val family = threatFamily(p[2])
                    val confidence = FindingConfidence.valueOf(p[3])
                    val weight = p[4].toInt().also { require(it in 1..100) }
                    val all = markerSet(p[5])
                    val any = markerSet(p[6])
                    require(all.isNotEmpty() || any.isNotEmpty())
                    rules += DetectionRule(id, family, confidence, weight, all, any)
                }
                "BRAND" -> {
                    require(p.size == 4)
                    val id = strictId(p[1])
                    val official = p[2].trim().lowercase()
                    require(official.matches(Regex("^[a-z0-9_]+(?:\\.[a-z0-9_]+)+$")))
                    val tokens = p[3].split(';').map { it.trim().lowercase() }.filter { it.length >= 3 }.toSet()
                    require(tokens.isNotEmpty())
                    brands += ProtectedBrandProfile(id, official, tokens)
                }
                "BRAND_SIGNER" -> {
                    require(p.size == 3)
                    val brandId = strictId(p[1])
                    val hash = p[2].trim().lowercase()
                    require(hash.matches(Regex("^[a-f0-9]{64}$")))
                    brandSigners.getOrPut(brandId) { linkedSetOf() }.add(hash)
                }
                "LINK" -> {
                    require(p.size == 6)
                    val fromId = strictId(p[1])
                    val toId = strictId(p[2])
                    require(fromId != toId)
                    val relation = ThreatGraphRelation.valueOf(p[3])
                    val confidence = FindingConfidence.valueOf(p[4])
                    val weight = p[5].toInt().also { require(it in 1..24) }
                    graphLinks += ThreatGraphLink(fromId, toId, relation, confidence, weight)
                }
                "MODEL" -> {
                    require(p.size == 3)
                    val feature = p[1].trim()
                    require(feature.matches(Regex("^[A-Z0-9_]{2,64}$")))
                    val weight = p[2].toDouble()
                    require(weight in -20.0..20.0)
                    require(model.put(feature, weight) == null) { "Duplicate model feature" }
                }
                "REASONING" -> {
                    require(p.size == 3)
                    val dim = p[1].trim()
                    require(dim.matches(Regex("^[a-z0-9_]{2,64}$")))
                    val weight = p[2].toDouble()
                    require(weight in -20.0..20.0)
                    val previousWeight = reasoning.put(dim, weight)
                    require(previousWeight == null || previousWeight == weight) {
                        "Conflicting reasoning dimension"
                    }
                }
                "REPUTATION" -> {
                    require(p.size == 7)
                    val kind = ReputationKind.valueOf(p[1])
                    val hash = p[2].trim().lowercase()
                    require(hash.matches(Regex("^[a-f0-9]{64}$")))
                    val id = strictId(p[3])
                    val family = threatFamily(p[4])
                    val confidence = FindingConfidence.valueOf(p[5])
                    val disposition = ReputationDisposition.valueOf(p[6])
                    val entry = ReputationIndicator(kind, hash, id, family, confidence, disposition)
                    require(reputation.put("$kind:$hash", entry) == null) { "Duplicate reputation indicator" }
                }
                "META" -> {
                    require(p.size == 7)
                    val id = strictId(p[1])
                    val source = p[2].trim().uppercase()
                    require(source.matches(Regex("^[A-Z0-9_.-]{2,64}$")))
                    val family = threatFamily(p[3])
                    val confidence = FindingConfidence.valueOf(p[4])
                    val firstSeen = optionalDate(p[5])
                    val lastSeen = optionalDate(p[6])
                    val entry = ThreatIntelMetadata(id, source, family, confidence, firstSeen, lastSeen)
                    require(metadata.put(id, entry) == null) { "Duplicate metadata id" }
                }
                else -> error("Unsupported detection row")
            }
        }
        require(rows == expectedCount)
        require(rules.map { it.id }.distinct().size == rules.size)
        require(brands.map { it.id }.distinct().size == brands.size)
        require(graphLinks.map { "${it.fromId}:${it.toId}:${it.relation}" }.distinct().size == graphLinks.size)
        val knownBrands = brands.map { it.id }.toSet()
        require(brandSigners.keys.all(knownBrands::contains))
        brandSigners.values.flatten().forEach { signerHash ->
            val rep = reputation["${ReputationKind.SIGNER}:$signerHash"]
            require(rep != null && rep.disposition == ReputationDisposition.SAFE && rep.confidence == FindingConfidence.CONFIRMED) {
                "Trusted brand signer must have CONFIRMED SAFE signer reputation"
            }
        }
        val enrichedBrands = brands.map { brand ->
            brand.copy(trustedSignerSha256 = brandSigners[brand.id]?.toSet().orEmpty())
        }
        return DetectionRuleset(rules, enrichedBrands, model, reasoning, reputation, metadata, graphLinks)
    }

    private fun threatFamily(value: String): ThreatFamily = runCatching {
        ThreatFamily.valueOf(value.trim())
    }.getOrDefault(ThreatFamily.UNKNOWN)

    private fun strictId(value: String): String = value.trim().also {
        require(it.matches(Regex("^[A-Z0-9_]{3,96}$")))
    }

    private fun optionalDate(value: String): String? {
        val text = value.trim()
        if (text == "-" || text.isEmpty()) return null
        require(text.matches(Regex("^\\d{4}-\\d{2}-\\d{2}(?:T\\d{2}:\\d{2}:\\d{2}Z)?$")))
        return text
    }

    private fun markerSet(value: String): Set<String> = value.split(';')
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .onEach { require(it.matches(Regex("^[A-Z0-9_]{2,64}$"))) }
        .toSet()
}
