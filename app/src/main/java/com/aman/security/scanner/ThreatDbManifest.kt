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
    val urlDbSha256: String?
) {
    companion object {
        fun parse(bytes: ByteArray): ThreatDbManifest {
            val json = JSONObject(bytes.toString(Charsets.UTF_8))
            val schema = json.getInt("schema")
            require(schema == 1 || schema == 2)
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
                urlDbSha256 = if (schema >= 2) json.getString("urlDbSha256").lowercase() else null
            )
            require(manifest.serial >= 1)
            require(manifest.version.length in 1..64)
            require(manifest.entries in 1..250_000)
            require(manifest.dbPath == "signatures.csv")
            require(manifest.dbSha256.matches(Regex("^[a-f0-9]{64}$")))
            if (schema >= 2) {
                require(manifest.urlEntries in 1..500_000)
                require(manifest.urlDbPath == "url_indicators.csv")
                require(manifest.urlDbSha256?.matches(Regex("^[a-f0-9]{64}$")) == true)
            }
            return manifest
        }
    }
}
