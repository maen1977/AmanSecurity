package com.aman.security.detection

import android.content.Context
import com.aman.security.BuildConfig
import com.aman.security.scanner.ThreatDbCrypto
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Privacy-preserving GitHub-hosted reputation lookup.
 *
 * Aman never places the full SHA-256 in the request URL. It requests a signed
 * shard using only the first two hexadecimal characters, verifies the detached
 * RSA signature locally, and performs the exact full-hash match on-device.
 */
class CloudReputationClient(private val context: Context) {
    sealed class Result {
        data object Disabled : Result()
        data object Unknown : Result()
        data class Known(
            val id: String,
            val family: ThreatFamily,
            val malicious: Boolean,
            val safe: Boolean
        ) : Result()
        data object NetworkError : Result()
        data object InvalidSignature : Result()
    }

    fun querySha256(sha256: String): Result {
        if (!CloudReputationPreferences(context).enabled) return Result.Disabled
        val base = BuildConfig.REPUTATION_SHARD_BASE_URL.trim()
        if (base.isBlank()) return Result.Disabled
        val normalized = sha256.lowercase()
        if (!normalized.matches(Regex("^[a-f0-9]{64}$"))) return Result.Unknown

        return try {
            require(base.startsWith("https://"))
            val prefix = normalized.substring(0, 2)
            val jsonBytes = download(base.trimEnd('/') + "/$prefix.json", MAX_SHARD_BYTES)
                ?: return Result.Unknown
            val signatureBytes = download(base.trimEnd('/') + "/$prefix.sig", MAX_SIGNATURE_BYTES)
                ?: return Result.InvalidSignature
            if (!ThreatDbCrypto.verifyDetached(context, jsonBytes, signatureBytes)) {
                return Result.InvalidSignature
            }
            val json = JSONObject(jsonBytes.toString(Charsets.UTF_8))
            if (json.optInt("schema", 0) != 1 || json.optString("kind") != "FILE" || json.optString("prefix") != prefix) {
                return Result.InvalidSignature
            }
            val entries = json.optJSONArray("entries") ?: return Result.Unknown
            for (i in 0 until entries.length()) {
                val entry = entries.optJSONObject(i) ?: continue
                if (!normalized.equals(entry.optString("sha256"), ignoreCase = true)) continue
                val disposition = entry.optString("disposition", "MALICIOUS")
                val family = runCatching {
                    ThreatFamily.valueOf(entry.optString("family", "UNKNOWN"))
                }.getOrDefault(ThreatFamily.UNKNOWN)
                return Result.Known(
                    id = entry.optString("id", "GITHUB_REPUTATION"),
                    family = family,
                    malicious = disposition == "MALICIOUS",
                    safe = disposition == "SAFE"
                )
            }
            Result.Unknown
        } catch (_: Exception) {
            Result.NetworkError
        }
    }

    private fun download(urlText: String, maxBytes: Int): ByteArray? {
        val url = URL(urlText)
        require(url.protocol == "https")
        val connection = (url.openConnection() as HttpURLConnection).apply {
            connectTimeout = 5_000
            readTimeout = 8_000
            requestMethod = "GET"
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json, application/octet-stream")
        }
        return try {
            when (connection.responseCode) {
                HttpURLConnection.HTTP_NOT_FOUND -> null
                HttpURLConnection.HTTP_OK -> {
                    val length = connection.contentLengthLong
                    if (length > maxBytes) return null
                    connection.inputStream.use { input ->
                        val output = ByteArrayOutputStream()
                        val buffer = ByteArray(4096)
                        var total = 0
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            total += read
                            if (total > maxBytes) return null
                            output.write(buffer, 0, read)
                        }
                        output.toByteArray()
                    }
                }
                else -> null
            }
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        private const val MAX_SHARD_BYTES = 512 * 1024
        private const val MAX_SIGNATURE_BYTES = 16 * 1024
    }
}

class CloudReputationPreferences(context: Context) {
    private val prefs = context.getSharedPreferences("aman_cloud_reputation", Context.MODE_PRIVATE)
    var enabled: Boolean
        get() = prefs.getBoolean("enabled", false)
        set(value) = prefs.edit().putBoolean("enabled", value).apply()
}
