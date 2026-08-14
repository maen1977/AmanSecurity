package com.aman.security.autonomous

import android.content.Context
import com.aman.security.scanner.SignatureDatabase
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipInputStream

/**
 * Aman 3.5 cloud consumer: one signed, pre-normalized package replaces seven phone-side feed jobs.
 * The handset never downloads or parses raw phishing/malware feeds.
 */
class AutonomousThreatUpdater(
    private val context: Context,
    private val database: SignatureDatabase = SignatureDatabase(context)
) {
    private val store = database.autonomousStore
    private val http = CloudThreatHttpClient()

    fun update(onProgress: ((AutonomousUpdateProgress) -> Unit)? = null): AutonomousUpdateResult {
        val attemptAt = System.currentTimeMillis()
        fun report(
            phase: AutonomousUpdatePhase,
            phaseProgress: Int = 0,
            downloaded: Long = 0L,
            totalBytes: Long = -1L,
            finished: Boolean = false,
            succeeded: Boolean? = null
        ) {
            onProgress?.invoke(
                AutonomousUpdateProgress(
                    sourceKey = AutonomousThreatStore.SOURCE_CLOUD_BUNDLE,
                    sourceIndex = 1,
                    totalSources = TOTAL_SOURCES,
                    completedSources = if (finished) 1 else 0,
                    phase = phase,
                    phaseProgress = phaseProgress.coerceIn(0, 100),
                    downloadedBytes = downloaded.coerceAtLeast(0L),
                    totalBytes = totalBytes,
                    sourceFinished = finished,
                    sourceSucceeded = succeeded
                )
            )
        }

        if (!http.configured()) {
            store.recordCloudFailure(attemptAt)
            report(AutonomousUpdatePhase.APPLYING, 100, finished = true, succeeded = false)
            return AutonomousUpdateResult.NoSourceAvailable("endpoint_not_configured")
        }

        return try {
            var lastError: Exception? = null
            var result: AutonomousUpdateResult? = null
            for (attempt in 0 until MAX_CLOUD_ATTEMPTS) {
                var staging: File? = null
                try {
                    if (attempt > 0) {
                        http.refreshCache()
                        report(AutonomousUpdatePhase.CONNECTING, 5)
                        Thread.sleep(RETRY_DELAY_MS)
                    }
                    report(AutonomousUpdatePhase.CONNECTING, 5)
                    val manifestBytes = http.getSmall("manifest.json", 64 * 1024)
                    report(AutonomousUpdatePhase.CONNECTING, 45)
                    val signatureBytes = http.getSmall("manifest.sig", 4 * 1024)
                    report(AutonomousUpdatePhase.PARSING, 20)
                    if (!CloudThreatSignatureVerifier.verify(context, manifestBytes, signatureBytes)) {
                        throw SecurityException("Cloud threat manifest signature rejected")
                    }
                    val manifest = CloudThreatManifest.parse(manifestBytes)
                    report(AutonomousUpdatePhase.PARSING, 100)

                    val installedSerial = store.installedSerial()
                    if (manifest.serial < installedSerial) throw SecurityException("Cloud threat rollback rejected")
                    if (manifest.serial == installedSerial) {
                        store.recordCloudUnchanged(manifest, attemptAt)
                        report(AutonomousUpdatePhase.APPLYING, 100, finished = true, succeeded = true)
                        val info = store.info()
                        return AutonomousUpdateResult.Success(info, changedSources = 0)
                    }

                    staging = store.createStagingDirectory()
                    val bundle = File(staging, "package.tmp")
                    val download = http.downloadBundle(manifest, bundle) { downloaded, total ->
                        val percent = if (total > 0L) ((downloaded * 100L) / total).toInt().coerceIn(0, 100) else 0
                        report(AutonomousUpdatePhase.DOWNLOADING, percent, downloaded, total)
                    }
                    if (download.sha256 != manifest.bundleSha256) throw SecurityException("Cloud threat bundle hash rejected")

                    report(AutonomousUpdatePhase.PARSING, 5, download.bytes, manifest.bundleBytes)
                    extractAndVerify(bundle, staging, manifest) { percent ->
                        report(AutonomousUpdatePhase.INDEXING, percent, download.bytes, manifest.bundleBytes)
                    }
                    bundle.delete()

                    report(AutonomousUpdatePhase.APPLYING, 30, download.bytes, manifest.bundleBytes)
                    val changed = store.installVerifiedPackage(staging, manifestBytes, manifest, attemptAt)
                    database.reloadAutonomous()
                    report(AutonomousUpdatePhase.APPLYING, 100, download.bytes, manifest.bundleBytes, finished = true, succeeded = true)
                    val info = store.info()
                    result = AutonomousUpdateResult.Success(info, changedSources = if (changed) 1 else 0)
                    break
                } catch (error: Exception) {
                    staging?.deleteRecursively()
                    lastError = error
                    if (!isRetryable(error) || attempt == MAX_CLOUD_ATTEMPTS - 1) throw error
                }
            }
            result ?: throw (lastError ?: IllegalStateException("Cloud threat update produced no result"))
        } catch (error: Exception) {
            store.recordCloudFailure(attemptAt)
            report(AutonomousUpdatePhase.APPLYING, 100, finished = true, succeeded = false)
            AutonomousUpdateResult.NoSourceAvailable(failureReason(error))
        }
    }

    private fun isRetryable(error: Exception): Boolean {
        val message = error.message.orEmpty()
        return !message.contains("endpoint not configured", ignoreCase = true) &&
            !message.contains("rollback rejected", ignoreCase = true) &&
            !message.contains("requires a newer Aman version", ignoreCase = true)
    }

    private fun failureReason(error: Exception): String {
        val message = error.message.orEmpty().replace(Regex("\\s+"), " ").trim()
        return when {
            message.isNotBlank() -> message.take(240)
            error is SecurityException -> "security_validation_failed"
            else -> error.javaClass.simpleName.take(120)
        }
    }

    private fun extractAndVerify(
        bundle: File,
        staging: File,
        manifest: CloudThreatManifest,
        onProgress: (Int) -> Unit
    ) {
        val allowed = CloudThreatManifest.REQUIRED_FILES
        val seen = linkedSetOf<String>()
        val totalExpected = manifest.files.values.sumOf { it.bytes }.coerceAtLeast(1L)
        var completedBytes = 0L
        val ioBuffer = ByteArray(32 * 1024)

        ZipInputStream(bundle.inputStream().buffered(32 * 1024)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                val name = entry.name
                if (entry.isDirectory || name !in allowed || name.contains('/') || name.contains('\\') || !seen.add(name)) {
                    throw SecurityException("Unexpected cloud threat package entry")
                }
                val meta = manifest.files.getValue(name)
                val target = File(staging, name)
                val digest = MessageDigest.getInstance("SHA-256")
                var written = 0L
                BufferedOutputStream(FileOutputStream(target), 32 * 1024).use { output ->
                    while (true) {
                        val read = zip.read(ioBuffer)
                        if (read < 0) break
                        written += read
                        if (written > meta.bytes) throw SecurityException("Cloud threat index exceeded signed size")
                        digest.update(ioBuffer, 0, read)
                        output.write(ioBuffer, 0, read)
                    }
                    output.flush()
                }
                if (written != meta.bytes) throw SecurityException("Cloud threat index size mismatch")
                val hash = digest.digest().joinToString("") { "%02x".format(it) }
                if (hash != meta.sha256) throw SecurityException("Cloud threat index hash mismatch")
                validateIndexFile(target, meta)
                completedBytes += written
                onProgress(((completedBytes * 100L) / totalExpected).toInt().coerceIn(0, 100))
                zip.closeEntry()
            }
        }
        if (seen != allowed) throw SecurityException("Cloud threat package incomplete")
        onProgress(100)
    }

    private fun validateIndexFile(file: File, meta: CloudThreatFileMeta) {
        var count = 0
        var previous: String? = null
        file.bufferedReader(Charsets.US_ASCII, 16 * 1024).useLines { lines ->
            lines.forEach { line ->
                when {
                    meta.name.endsWith(".sha256") -> {
                        if (!HASH.matches(line)) throw SecurityException("Invalid cloud SHA-256 index")
                        if (previous != null && previous!! >= line) throw SecurityException("Cloud SHA-256 index is not strictly sorted")
                    }
                    meta.name == AutonomousThreatStore.FILE_ANDROID_CVES -> {
                        if (!CVE.matches(line)) throw SecurityException("Invalid Android CVE index")
                        if (previous != null && previous!! >= line) throw SecurityException("Android CVE index is not strictly sorted")
                    }
                }
                previous = line
                count++
                if (count > meta.entries) throw SecurityException("Cloud threat index entry overflow")
            }
        }
        if (count != meta.entries) throw SecurityException("Cloud threat index count mismatch")
    }

    companion object {
        const val TOTAL_SOURCES = 1
        private const val MAX_CLOUD_ATTEMPTS = 3
        private const val RETRY_DELAY_MS = 1_500L
        private val HASH = Regex("^[a-f0-9]{64}$")
        private val CVE = Regex("^CVE-20\\d{2}-\\d{4,8}$")
    }
}
