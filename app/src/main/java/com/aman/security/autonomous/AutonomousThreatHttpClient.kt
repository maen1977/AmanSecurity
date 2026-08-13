package com.aman.security.autonomous

import android.content.Context
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.SocketTimeoutException

class AutonomousThreatHttpClient(context: Context) {
    private val prefs = context.getSharedPreferences("aman_autonomous_http_v1", Context.MODE_PRIVATE)

    data class Response(val bytes: ByteArray?, val notModified: Boolean)

    /**
     * Downloads one bounded text feed. Progress callbacks are deliberately throttled so the
     * UI can prove that an update is moving without turning SharedPreferences writes into a
     * background performance cost. Redirects stay disabled at HttpURLConnection level; one
     * explicitly allowlisted data-feed redirect can be followed manually.
     */
    fun get(
        urlText: String,
        maxBytes: Int,
        accept: String,
        cacheKey: String,
        onProgress: ((downloadedBytes: Long, totalBytes: Long) -> Unit)? = null,
        maxDurationMs: Long = DEFAULT_DOWNLOAD_DEADLINE_MS
    ): Response {
        require(AutonomousSourcePolicy.allowed(urlText))
        require(maxDurationMs in 10_000L..5 * 60_000L)
        return getInternal(
            urlText = urlText,
            maxBytes = maxBytes,
            accept = accept,
            cacheKey = cacheKey,
            onProgress = onProgress,
            maxDurationMs = maxDurationMs,
            startedAtNanos = System.nanoTime(),
            redirectDepth = 0
        )
    }

    private fun getInternal(
        urlText: String,
        maxBytes: Int,
        accept: String,
        cacheKey: String,
        onProgress: ((downloadedBytes: Long, totalBytes: Long) -> Unit)?,
        maxDurationMs: Long,
        startedAtNanos: Long,
        redirectDepth: Int
    ): Response {
        fun enforceDeadline() {
            val elapsedMs = (System.nanoTime() - startedAtNanos) / 1_000_000L
            if (elapsedMs > maxDurationMs) throw SocketTimeoutException("Threat source download deadline exceeded")
        }

        enforceDeadline()
        val url = URI(urlText).toURL()
        val connection = (url.openConnection() as HttpURLConnection).apply {
            connectTimeout = 12_000
            readTimeout = 25_000
            instanceFollowRedirects = false
            requestMethod = "GET"
            setRequestProperty("User-Agent", "AmanSecurity/3.4 autonomous-threat-intelligence")
            setRequestProperty("Accept", accept)
            prefs.getString("etag_$cacheKey", null)?.let { setRequestProperty("If-None-Match", it) }
            prefs.getString("modified_$cacheKey", null)?.let { setRequestProperty("If-Modified-Since", it) }
        }
        try {
            val code = connection.responseCode
            enforceDeadline()

            if (code in REDIRECT_CODES) {
                if (redirectDepth >= MAX_REDIRECTS) throw java.io.IOException("Unexpected threat-feed redirect chain")
                val location = connection.getHeaderField("Location") ?: throw java.io.IOException("Threat-feed redirect missing location")
                val redirected = URI(urlText).resolve(location).toString()
                if (!AutonomousSourcePolicy.allowedRedirect(urlText, redirected)) {
                    throw java.io.IOException("Threat-feed redirect rejected")
                }
                return getInternal(
                    urlText = redirected,
                    maxBytes = maxBytes,
                    accept = accept,
                    cacheKey = cacheKey,
                    onProgress = onProgress,
                    maxDurationMs = maxDurationMs,
                    startedAtNanos = startedAtNanos,
                    redirectDepth = redirectDepth + 1
                )
            }

            if (code == HttpURLConnection.HTTP_NOT_MODIFIED) {
                onProgress?.invoke(0L, 0L)
                return Response(null, true)
            }
            if (code != HttpURLConnection.HTTP_OK) throw java.io.IOException("HTTP $code")
            val length = connection.contentLengthLong
            if (length > maxBytes) throw java.io.IOException("Response too large")
            val reportedTotal = length.takeIf { it > 0L } ?: -1L
            onProgress?.invoke(0L, reportedTotal)
            val bytes = connection.inputStream.use { input ->
                val out = ByteArrayOutputStream()
                val buffer = ByteArray(16 * 1024)
                var total = 0L
                var lastReportedBytes = 0L
                var lastReportedAt = System.currentTimeMillis()
                while (true) {
                    enforceDeadline()
                    val read = input.read(buffer)
                    enforceDeadline()
                    if (read < 0) break
                    total += read
                    if (total > maxBytes) throw java.io.IOException("Response too large")
                    out.write(buffer, 0, read)
                    val now = System.currentTimeMillis()
                    if (total - lastReportedBytes >= PROGRESS_BYTE_STEP || now - lastReportedAt >= PROGRESS_TIME_STEP_MS) {
                        onProgress?.invoke(total, reportedTotal)
                        lastReportedBytes = total
                        lastReportedAt = now
                    }
                }
                onProgress?.invoke(total, reportedTotal)
                out.toByteArray()
            }
            if (!AutonomousSourcePolicy.textPayloadAllowed(bytes)) throw java.io.IOException("Executable/archive payload rejected")
            val editor = prefs.edit()
            connection.getHeaderField("ETag")?.let { editor.putString("etag_$cacheKey", it) }
            connection.getHeaderField("Last-Modified")?.let { editor.putString("modified_$cacheKey", it) }
            editor.apply()
            return Response(bytes, false)
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        private const val PROGRESS_BYTE_STEP = 512L * 1024L
        private const val PROGRESS_TIME_STEP_MS = 800L
        private const val DEFAULT_DOWNLOAD_DEADLINE_MS = 75_000L
        private const val MAX_REDIRECTS = 1
        private val REDIRECT_CODES = setOf(
            HttpURLConnection.HTTP_MOVED_PERM,
            HttpURLConnection.HTTP_MOVED_TEMP,
            HttpURLConnection.HTTP_SEE_OTHER,
            307,
            308
        )
    }
}
