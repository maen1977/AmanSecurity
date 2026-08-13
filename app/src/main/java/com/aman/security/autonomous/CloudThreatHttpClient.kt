package com.aman.security.autonomous

import com.aman.security.BuildConfig
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URI
import java.security.MessageDigest
import java.util.Locale

class CloudThreatHttpClient {
    data class DownloadResult(val bytes: Long, val sha256: String)

    private val baseUrl: String = BuildConfig.AMAN_THREAT_DB_BASE_URL.trim().trimEnd('/')

    fun configured(): Boolean = validateBase(baseUrl)

    fun getSmall(name: String, maxBytes: Int): ByteArray {
        require(name == "manifest.json" || name == "manifest.sig")
        require(maxBytes in 512..128 * 1024)
        val connection = open(urlFor(name))
        try {
            val code = connection.responseCode
            if (code != HttpURLConnection.HTTP_OK) throw java.io.IOException("Cloud threat HTTP $code")
            val length = connection.contentLengthLong
            if (length > maxBytes) throw java.io.IOException("Cloud threat response too large")
            return connection.inputStream.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (out.size() + read > maxBytes) throw java.io.IOException("Cloud threat response too large")
                    out.write(buffer, 0, read)
                }
                out.toByteArray()
            }
        } finally {
            connection.disconnect()
        }
    }

    fun downloadBundle(
        manifest: CloudThreatManifest,
        target: File,
        onProgress: (downloaded: Long, total: Long) -> Unit
    ): DownloadResult {
        require(target.parentFile?.isDirectory == true)
        val connection = open(urlFor(manifest.bundlePath), readTimeoutMs = 30_000)
        val started = System.nanoTime()
        try {
            val code = connection.responseCode
            if (code != HttpURLConnection.HTTP_OK) throw java.io.IOException("Cloud threat bundle HTTP $code")
            val announced = connection.contentLengthLong
            if (announced > 0L && announced != manifest.bundleBytes) throw java.io.IOException("Cloud threat bundle size mismatch")
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            var lastReportBytes = 0L
            var lastReportAt = System.currentTimeMillis()
            onProgress(0L, manifest.bundleBytes)
            connection.inputStream.use { input ->
                FileOutputStream(target).use { output ->
                    val buffer = ByteArray(32 * 1024)
                    while (true) {
                        if ((System.nanoTime() - started) / 1_000_000L > DOWNLOAD_DEADLINE_MS) {
                            throw SocketTimeoutException("Cloud threat bundle download deadline exceeded")
                        }
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > manifest.bundleBytes || total > CloudThreatManifest.MAX_BUNDLE_BYTES) {
                            throw java.io.IOException("Cloud threat bundle exceeded signed size")
                        }
                        digest.update(buffer, 0, read)
                        output.write(buffer, 0, read)
                        val now = System.currentTimeMillis()
                        if (total - lastReportBytes >= 256 * 1024 || now - lastReportAt >= 700L) {
                            onProgress(total, manifest.bundleBytes)
                            lastReportBytes = total
                            lastReportAt = now
                        }
                    }
                    output.fd.sync()
                }
            }
            if (total != manifest.bundleBytes) throw java.io.IOException("Cloud threat bundle incomplete")
            onProgress(total, manifest.bundleBytes)
            return DownloadResult(total, digest.digest().joinToString("") { "%02x".format(it) })
        } finally {
            connection.disconnect()
        }
    }

    private fun open(urlText: String, readTimeoutMs: Int = 20_000): HttpURLConnection =
        (URI(urlText).toURL().openConnection() as HttpURLConnection).apply {
            connectTimeout = 12_000
            readTimeout = readTimeoutMs
            instanceFollowRedirects = false
            requestMethod = "GET"
            setRequestProperty("User-Agent", "AmanSecurity/${BuildConfig.VERSION_NAME} cloud-intelligence-consumer")
            setRequestProperty("Accept", "application/octet-stream,application/json;q=0.9")
            setRequestProperty("Cache-Control", "no-transform")
        }

    private fun urlFor(name: String): String {
        check(validateBase(baseUrl)) { "Aman cloud threat endpoint is not configured" }
        require(name.matches(Regex("^[a-z0-9.-]{3,64}$")))
        return "$baseUrl/$name"
    }

    companion object {
        private const val DOWNLOAD_DEADLINE_MS = 90_000L

        fun validateBase(value: String): Boolean {
            if (value.isBlank()) return false
            val uri = runCatching { URI(value) }.getOrNull() ?: return false
            if (uri.scheme?.lowercase(Locale.ROOT) != "https" || uri.userInfo != null || uri.query != null || uri.fragment != null) return false
            if (uri.host?.lowercase(Locale.ROOT) != "raw.githubusercontent.com") return false
            val parts = uri.path.orEmpty().split('/').filter(String::isNotBlank)
            return parts.size == 4 &&
                parts[0].matches(Regex("^[A-Za-z0-9_.-]{1,100}$")) &&
                parts[1].matches(Regex("^[A-Za-z0-9_.-]{1,100}$")) &&
                parts[2] == "AmanSecurity-Threat-DB" && parts[3] == "main"
        }
    }
}
