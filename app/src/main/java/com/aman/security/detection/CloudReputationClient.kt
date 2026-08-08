package com.aman.security.detection

import android.content.Context
import com.aman.security.BuildConfig
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class CloudReputationClient(private val context: Context) {
    sealed class Result {
        data object Disabled : Result()
        data object Unknown : Result()
        data class Known(val id: String, val family: ThreatFamily, val malicious: Boolean) : Result()
        data object NetworkError : Result()
    }

    fun querySha256(sha256: String): Result {
        if (!CloudReputationPreferences(context).enabled) return Result.Disabled
        val base = BuildConfig.REPUTATION_API_BASE_URL.trim()
        if (base.isBlank()) return Result.Disabled
        if (!sha256.matches(Regex("^[a-fA-F0-9]{64}$"))) return Result.Unknown
        return try {
            require(base.startsWith("https://"))
            val url = URL(base.trimEnd('/') + "/v1/hash/" + sha256.lowercase())
            val connection = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 5_000
                readTimeout = 8_000
                requestMethod = "GET"
                instanceFollowRedirects = false
                setRequestProperty("Accept", "application/json")
            }
            try {
                when (connection.responseCode) {
                    HttpURLConnection.HTTP_NOT_FOUND -> Result.Unknown
                    HttpURLConnection.HTTP_OK -> {
                        val bytes = connection.inputStream.use { input ->
                            val out = java.io.ByteArrayOutputStream()
                            val buffer = ByteArray(4096)
                            var total = 0
                            while (true) {
                                val read = input.read(buffer)
                                if (read < 0) break
                                total += read
                                if (total > 32 * 1024) return Result.NetworkError
                                out.write(buffer, 0, read)
                            }
                            out.toByteArray()
                        }
                        val json = JSONObject(bytes.toString(Charsets.UTF_8))
                        val malicious = json.optBoolean("malicious", false)
                        val id = json.optString("id", "CLOUD_REPUTATION")
                        val family = runCatching { ThreatFamily.valueOf(json.optString("family", "UNKNOWN")) }.getOrDefault(ThreatFamily.UNKNOWN)
                        Result.Known(id, family, malicious)
                    }
                    else -> Result.NetworkError
                }
            } finally {
                connection.disconnect()
            }
        } catch (_: Exception) {
            Result.NetworkError
        }
    }
}

class CloudReputationPreferences(context: Context) {
    private val prefs = context.getSharedPreferences("aman_cloud_reputation", Context.MODE_PRIVATE)
    var enabled: Boolean
        get() = prefs.getBoolean("enabled", false)
        set(value) = prefs.edit().putBoolean("enabled", value).apply()
}
