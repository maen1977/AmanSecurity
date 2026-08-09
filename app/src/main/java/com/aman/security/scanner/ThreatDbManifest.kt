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
    val dbSha256: String,
    val urlEntries: Int,
    val urlDbPath: String?,
    val urlDbSha256: String?,
    val apkIdentityEntries: Int,
    val apkIdentityDbPath: String?,
    val apkIdentityDbSha256: String?,
    val detectionEntries: Int,
    val detectionDbPath: String?,
    val detectionDbSha256: String?
) {
    companion object {
        fun parse(bytes: ByteArray): ThreatDbManifest {
            val json = JSONObject(bytes.toString(Charsets.UTF_8))
            val schema = json.getInt("schema")
            require(schema in 1..4)
            val manifest = ThreatDbManifest(
                schema = schema,
                serial = json.getLong("serial"),
                version = json.getString("version"),
                generatedAt = json.getString("generatedAt"),
                minAppVersionCode = json.getInt("minAppVersionCode"),
                entries = json.getInt("entries"),
                dbPath = json.getString("dbPath"),
                dbSha256 = json.getString("dbSha256").lowercase(),
                urlEntries = if (schema >= 2) json.getInt("urlEntries") else 0,
                urlDbPath = if (schema >= 2) json.getString("urlDbPath") else null,
                urlDbSha256 = if (schema >= 2) json.getString("urlDbSha256").lowercase() else null,
                apkIdentityEntries = if (schema >= 3) json.getInt("apkIdentityEntries") else 0,
                apkIdentityDbPath = if (schema >= 3) json.getString("apkIdentityDbPath") else null,
                apkIdentityDbSha256 = if (schema >= 3) json.getString("apkIdentityDbSha256").lowercase() else null,
                detectionEntries = if (schema >= 4) json.getInt("detectionEntries") else 0,
                detectionDbPath = if (schema >= 4) json.getString("detectionDbPath") else null,
                detectionDbSha256 = if (schema >= 4) json.getString("detectionDbSha256").lowercase() else null
            )
            require(manifest.serial >= 1)
            require(manifest.version.length in 1..64)
            require(manifest.entries in 1..1_000_000)
            require(manifest.dbPath == "signatures.csv")
            require(manifest.dbSha256.matches(Regex("^[a-f0-9]{64}$")))
            if (schema >= 2) {
                require(manifest.urlEntries in 1..2_000_000)
                require(manifest.urlDbPath == "url_indicators.csv")
                require(manifest.urlDbSha256?.matches(Regex("^[a-f0-9]{64}$")) == true)
            }
            if (schema >= 3) {
                require(manifest.apkIdentityEntries in 1..1_000_000)
                require(manifest.apkIdentityDbPath == "apk_indicators.csv")
                require(manifest.apkIdentityDbSha256?.matches(Regex("^[a-f0-9]{64}$")) == true)
            }
            if (schema >= 4) {
                require(manifest.detectionEntries in 1..500_000)
                require(manifest.detectionDbPath == "detection_rules.csv")
                require(manifest.detectionDbSha256?.matches(Regex("^[a-f0-9]{64}$")) == true)
            }
            return manifest
        }
    }
}
