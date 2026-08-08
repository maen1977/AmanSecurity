package com.aman.security.scanner

import android.content.Context

object ThreatDbValidator {
    data class ValidatedPackage(
        val manifest: ThreatDbManifest,
        val signatures: Map<String, ThreatSignature>
    )

    fun validate(
        context: Context,
        manifestBytes: ByteArray,
        signatureBytes: ByteArray,
        databaseBytes: ByteArray
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
            .mapNotNull(::parseLine)
            .toList()
        require(parsed.size == manifest.entries)
        require(parsed.map { it.sha256 }.distinct().size == parsed.size)

        return ValidatedPackage(manifest, parsed.associateBy { it.sha256 })
    }

    private fun parseLine(line: String): ThreatSignature? {
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
}
