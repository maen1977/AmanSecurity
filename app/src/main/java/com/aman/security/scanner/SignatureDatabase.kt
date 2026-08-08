package com.aman.security.scanner

import android.content.Context

class SignatureDatabase(private val context: Context) {
    val version: String by lazy { loadVersion() }
    private val signatures: Map<String, ThreatSignature> by lazy { loadSignatures() }

    fun find(sha256: String): ThreatSignature? = signatures[sha256.lowercase()]

    private fun loadVersion(): String = context.assets.open("signature_db_version.txt")
        .bufferedReader()
        .use { it.readText().trim() }

    private fun loadSignatures(): Map<String, ThreatSignature> {
        return context.assets.open("signatures_v1.csv")
            .bufferedReader()
            .useLines { lines ->
                lines
                    .filter { it.isNotBlank() && !it.startsWith("#") }
                    .mapNotNull(::parseLine)
                    .associateBy { it.sha256 }
            }
    }

    private fun parseLine(line: String): ThreatSignature? {
        val parts = line.split('|')
        if (parts.size != 3) return null
        val hash = parts[0].trim().lowercase()
        if (!hash.matches(Regex("^[a-f0-9]{64}$"))) return null
        val classification = runCatching { ScanClassification.valueOf(parts[2].trim()) }.getOrNull()
            ?: return null
        return ThreatSignature(hash, parts[1].trim(), classification)
    }
}
