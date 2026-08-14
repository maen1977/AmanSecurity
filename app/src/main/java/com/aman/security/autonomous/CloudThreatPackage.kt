package com.aman.security.autonomous

import android.content.Context
import com.aman.security.BuildConfig
import org.json.JSONObject
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Locale

data class CloudThreatFileMeta(
    val name: String,
    val sha256: String,
    val entries: Int,
    val bytes: Long
)

data class CloudThreatManifest(
    val schema: Int,
    val serial: Long,
    val version: String,
    val generatedAt: String,
    val generatedAtEpochMs: Long,
    val minAppVersionCode: Int,
    val bundlePath: String,
    val bundleSha256: String,
    val bundleBytes: Long,
    val latestAndroidSecurityPatch: String?,
    val files: Map<String, CloudThreatFileMeta>
) {
    companion object {
        val REQUIRED_FILES = linkedSetOf(
            "malware_files.sha256",
            "phishing_primary.sha256",
            "phishing_openphish.sha256",
            "phishing_community.sha256",
            "malware_url_hosts.sha256",
            "c2_hosts.sha256",
            "android_cves.txt"
        )

        fun parse(bytes: ByteArray): CloudThreatManifest {
            require(bytes.size in 2..64 * 1024) { "Cloud manifest size invalid" }
            val json = JSONObject(bytes.toString(Charsets.UTF_8))
            val schema = json.getInt("schema")
            require(schema == 1) { "Unsupported cloud threat schema" }
            val generatedAt = json.getString("generatedAt")
            val generatedEpoch = Instant.parse(generatedAt).toEpochMilli()
            require(generatedEpoch > 0L && generatedEpoch <= System.currentTimeMillis() + 24 * 60 * 60_000L) {
                "Cloud threat timestamp invalid"
            }
            val fileObject = json.getJSONObject("files")
            val files = linkedMapOf<String, CloudThreatFileMeta>()
            REQUIRED_FILES.forEach { name ->
                require(fileObject.has(name)) { "Missing cloud threat file" }
                val item = fileObject.getJSONObject(name)
                val meta = CloudThreatFileMeta(
                    name = name,
                    sha256 = item.getString("sha256").lowercase(Locale.ROOT),
                    entries = item.getInt("entries"),
                    bytes = item.getLong("bytes")
                )
                require(meta.sha256.matches(HASH))
                require(meta.entries in 0..maxEntries(name))
                require(meta.bytes in 0L..maxBytes(name))
                if (name.endsWith(".sha256")) require(meta.bytes == meta.entries.toLong() * 65L)
                files[name] = meta
            }
            require(fileObject.keys().asSequence().toSet() == REQUIRED_FILES)
            val patch = json.optString("latestAndroidSecurityPatch", "").takeIf(String::isNotBlank)
            if (patch != null) require(patch.matches(Regex("^20\\d{2}-\\d{2}-(?:01|05)$")))
            return CloudThreatManifest(
                schema = schema,
                serial = json.getLong("serial").also { require(it >= 1L) },
                version = json.getString("version").also { require(it.length in 1..64) },
                generatedAt = generatedAt,
                generatedAtEpochMs = generatedEpoch,
                minAppVersionCode = json.getInt("minAppVersionCode").also { require(it in 1..100_000) },
                bundlePath = json.getString("bundlePath").also {
                    require(it.matches(Regex("^aman-threat-db-[0-9]+\\.zip$")))
                },
                bundleSha256 = json.getString("bundleSha256").lowercase(Locale.ROOT).also { require(it.matches(HASH)) },
                bundleBytes = json.getLong("bundleBytes").also { require(it in 1L..MAX_BUNDLE_BYTES) },
                latestAndroidSecurityPatch = patch,
                files = files
            ).also {
                require(it.minAppVersionCode <= BuildConfig.VERSION_CODE) { "Threat database requires a newer Aman version" }
            }
        }

        private fun maxEntries(name: String): Int = when (name) {
            "malware_files.sha256" -> 100_000
            "phishing_primary.sha256" -> 120_000
            "phishing_openphish.sha256" -> 80_000
            "phishing_community.sha256" -> 60_000
            "malware_url_hosts.sha256" -> 120_000
            "c2_hosts.sha256" -> 50_000
            "android_cves.txt" -> 20_000
            else -> 0
        }

        private fun maxBytes(name: String): Long = if (name.endsWith(".sha256")) maxEntries(name).toLong() * 65L else 2L * 1024L * 1024L
        private val HASH = Regex("^[a-f0-9]{64}$")
        const val MAX_BUNDLE_BYTES = 24L * 1024L * 1024L
    }
}

object CloudThreatSignatureVerifier {
    fun verify(context: Context, manifest: ByteArray, signatureBytes: ByteArray): Boolean = runCatching {
        require(signatureBytes.size in 256..1024)
        val pem = context.assets.open("keys/aman-threat-db-public.pem").bufferedReader().use { it.readText() }
        val base64 = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .filterNot(Char::isWhitespace)
        val keyBytes = Base64.getDecoder().decode(base64)
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyBytes))
        Signature.getInstance("SHA256withRSA").run {
            initVerify(publicKey)
            update(manifest)
            verify(signatureBytes)
        }
    }.getOrDefault(false)
}
