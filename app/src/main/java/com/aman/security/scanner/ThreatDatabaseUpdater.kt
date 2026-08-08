package com.aman.security.scanner

import android.content.Context
import com.aman.security.BuildConfig
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

class ThreatDatabaseUpdater(
    private val context: Context,
    private val database: SignatureDatabase
) {
    sealed class Result {
        data object UpToDate : Result()
        data class Updated(val version: String, val fileEntries: Int, val urlEntries: Int) : Result()
        data object InvalidSignature : Result()
        data object InvalidDatabase : Result()
        data object NetworkError : Result()
    }

    fun update(): Result {
        return try {
            val base = BuildConfig.THREAT_DB_BASE_URL
            require(base.startsWith("https://"))
            val manifestBytes = download(base + "manifest.json", 64 * 1024)
            val signatureBytes = download(base + "manifest.sig", 16 * 1024)

            if (!ThreatDbCrypto.verifyManifest(context, manifestBytes, signatureBytes)) {
                return Result.InvalidSignature
            }
            val manifest = runCatching { ThreatDbManifest.parse(manifestBytes) }
                .getOrElse { return Result.InvalidDatabase }
            if (manifest.minAppVersionCode > BuildConfig.VERSION_CODE) return Result.InvalidDatabase
            if (manifest.schema < 2) return Result.InvalidDatabase
            if (manifest.serial <= database.info.serial) return Result.UpToDate

            val dbBytes = download(base + manifest.dbPath, 16 * 1024 * 1024)
            val urlBytes = if (manifest.schema >= 2) {
                download(base + requireNotNull(manifest.urlDbPath), 32 * 1024 * 1024)
            } else null
            val validated = runCatching {
                ThreatDbValidator.validate(context, manifestBytes, signatureBytes, dbBytes, urlBytes)
            }.getOrElse { return Result.InvalidDatabase }

            ThreatDbStorage(context).install(manifestBytes, signatureBytes, dbBytes, urlBytes)
            database.reloadAfterUpdate()
            Result.Updated(
                validated.manifest.version,
                validated.signatures.size,
                validated.urlIndicators.size
            )
        } catch (_: java.io.IOException) {
            Result.NetworkError
        } catch (_: Exception) {
            Result.InvalidDatabase
        }
    }

    private fun download(urlText: String, maxBytes: Int): ByteArray {
        val url = URL(urlText)
        require(url.protocol == "https")
        val connection = (url.openConnection() as HttpURLConnection).apply {
            connectTimeout = 10_000
            readTimeout = 20_000
            instanceFollowRedirects = false
            requestMethod = "GET"
            setRequestProperty("Accept", "application/octet-stream, application/json, text/plain")
        }
        try {
            if (connection.responseCode != HttpURLConnection.HTTP_OK) throw java.io.IOException()
            val length = connection.contentLengthLong
            if (length > maxBytes) throw java.io.IOException()
            return connection.inputStream.use { input ->
                val out = ByteArrayOutputStream()
                val buffer = ByteArray(16 * 1024)
                var total = 0
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > maxBytes) throw java.io.IOException()
                    out.write(buffer, 0, read)
                }
                out.toByteArray()
            }
        } finally {
            connection.disconnect()
        }
    }
}
