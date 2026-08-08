package com.aman.security.scanner

import org.json.JSONObject

data class ThreatDbManifest(
    val schema: Int,
    val serial: Long,
    val version: String,
    val generatedAt: String,
    val minAppVersionCode: Int,
    val entries: Int,
    val dbPath: String,
    val dbSha256: String
) {
    companion object {
        fun parse(bytes: ByteArray): ThreatDbManifest {
            val json = JSONObject(bytes.toString(Charsets.UTF_8))
            val manifest = ThreatDbManifest(
                schema = json.getInt("schema"),
                serial = json.getLong("serial"),
                version = json.getString("version"),
                generatedAt = json.getString("generatedAt"),
                minAppVersionCode = json.getInt("minAppVersionCode"),
                entries = json.getInt("entries"),
                dbPath = json.getString("dbPath"),
                dbSha256 = json.getString("dbSha256").lowercase()
            )
            require(manifest.schema == 1)
            require(manifest.serial >= 1)
            require(manifest.version.length in 1..64)
            require(manifest.entries in 1..250_000)
            require(manifest.dbPath == "signatures.csv")
            require(manifest.dbSha256.matches(Regex("^[a-f0-9]{64}$")))
            return manifest
        }
    }
}
