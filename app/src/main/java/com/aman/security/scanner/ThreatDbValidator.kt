package com.aman.security.scanner

import android.content.Context

object ThreatDbValidator {
    data class ValidatedPackage(
        val manifest: ThreatDbManifest,
        val signatures: Map<String, ThreatSignature>,
        val urlIndicators: Map<String, UrlThreatIndicator>
    )

    fun validate(
        context: Context,
        manifestBytes: ByteArray,
        signatureBytes: ByteArray,
        databaseBytes: ByteArray,
        urlDatabaseBytes: ByteArray? = null
    ): ValidatedPackage {
        require(manifestBytes.size <= 64 * 1024)
        require(signatureBytes.size <= 16 * 1024)
        require(databaseBytes.size <= 16 * 1024 * 1024)
        require(ThreatDbCrypto.verifyManifest(context, manifestBytes, signatureBytes))

        val manifest = ThreatDbManifest.parse(manifestBytes)
        require(manifest.minAppVersionCode <= com.aman.security.BuildConfig.VERSION_CODE)
        require(ThreatDbCrypto.sha256(databaseBytes) == manifest.dbSha256)

        val parsed = databaseBytes.toString(Charsets.UTF_8)
            .lineSequence()
            .filter { it.isNotBlank() && !it.trimStart().startsWith("#") }
            .mapNotNull(::parseFileLine)
            .toList()
        require(parsed.size == manifest.entries)
        require(parsed.map { it.sha256 }.distinct().size == parsed.size)

        val urls = if (manifest.schema >= 2) {
            val urlBytes = requireNotNull(urlDatabaseBytes)
            require(urlBytes.size <= 32 * 1024 * 1024)
            require(ThreatDbCrypto.sha256(urlBytes) == manifest.urlDbSha256)
            val parsedUrls = urlBytes.toString(Charsets.UTF_8)
                .lineSequence()
                .filter { it.isNotBlank() && !it.trimStart().startsWith("#") }
                .mapNotNull(::parseUrlLine)
                .toList()
            require(parsedUrls.size == manifest.urlEntries)
            require(parsedUrls.map { "${it.kind}:${it.sha256}" }.distinct().size == parsedUrls.size)
            parsedUrls
        } else {
            emptyList()
        }

        return ValidatedPackage(
            manifest = manifest,
            signatures = parsed.associateBy { it.sha256 },
            urlIndicators = urls.associateBy { "${it.kind}:${it.sha256}" }
        )
    }

    private fun parseFileLine(line: String): ThreatSignature? {
        val parts = line.split('|')
        if (parts.size != 3) return null
        val hash = parts[0].trim().lowercase()
        if (!hash.matches(Regex("^[a-f0-9]{64}$"))) return null
        val id = parts[1].trim()
        if (!id.matches(Regex("^[A-Z0-9_]{3,96}$"))) return null
        val classification = runCatching { ScanClassification.valueOf(parts[2].trim()) }.getOrNull()
            ?: return null
        if (classification == ScanClassification.NO_KNOWN_THREAT || classification == ScanClassification.UNKNOWN_APK) {
            return null
        }
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
}
