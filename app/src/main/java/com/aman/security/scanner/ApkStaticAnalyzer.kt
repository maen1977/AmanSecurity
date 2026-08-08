package com.aman.security.scanner

import android.Manifest
import android.content.ContentResolver
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipFile

class ApkStaticAnalyzer(
    private val context: Context,
    private val database: SignatureDatabase
) {
    private val resolver: ContentResolver = context.contentResolver
    private val packageManager: PackageManager = context.packageManager

    fun analyze(uri: Uri, expectedSha256: String): ApkStaticAnalysis {
        val directory = File(context.cacheDir, "apk-analysis").apply { mkdirs() }
        val temp = File(directory, "${UUID.randomUUID()}.apk")
        return try {
            val copiedHash = copyBounded(uri, temp) ?: return ApkStaticAnalysis(ApkAnalysisState.FAILED)
            if (!copiedHash.equals(expectedSha256, ignoreCase = true)) {
                return ApkStaticAnalysis(ApkAnalysisState.SOURCE_CHANGED)
            }
            analyzeFile(temp)
        } catch (_: SizeLimitExceeded) {
            ApkStaticAnalysis(ApkAnalysisState.LIMIT_EXCEEDED)
        } catch (_: Exception) {
            ApkStaticAnalysis(ApkAnalysisState.FAILED)
        } finally {
            temp.delete()
        }
    }

    private fun analyzeFile(file: File): ApkStaticAnalysis {
        val zipSignals = try {
            inspectArchive(file)
        } catch (_: java.util.zip.ZipException) {
            return ApkStaticAnalysis(ApkAnalysisState.INVALID_APK)
        }
        val packageInfo = archivePackageInfo(file) ?: return ApkStaticAnalysis(ApkAnalysisState.INVALID_APK)
        val signals = linkedSetOf<ApkRiskSignal>()
        signals += manifestSignals(packageInfo)
        signals += zipSignals.signals

        val certificateHash = signingCertificateSha256(packageInfo)
        val signerIndicator = certificateHash?.let { database.findApk(ApkIndicatorKind.SIGNER, it) }
        val packageHash = packageInfo.packageName
            .takeIf { it.isNotBlank() }
            ?.let { sha256Text(it) }
        val packageIndicator = packageHash?.let { database.findApk(ApkIndicatorKind.PACKAGE, it) }
        val identityIndicator = selectIdentityIndicator(signerIndicator, packageIndicator)

        val evaluation = ApkRiskEvaluator.evaluate(signals)
        val components = (packageInfo.activities?.size ?: 0) +
            (packageInfo.services?.size ?: 0) +
            (packageInfo.receivers?.size ?: 0) +
            (packageInfo.providers?.size ?: 0)

        return ApkStaticAnalysis(
            state = ApkAnalysisState.VALID,
            riskScore = evaluation.score,
            riskLevel = evaluation.level,
            signals = evaluation.signals,
            requestedPermissionCount = packageInfo.requestedPermissions?.size ?: 0,
            componentCount = components,
            dexFileCount = zipSignals.dexFileCount,
            nativeLibraryCount = zipSignals.nativeLibraryCount,
            signingCertificateSha256 = certificateHash,
            identityIndicator = identityIndicator,
            codeScanTruncated = zipSignals.codeScanTruncated
        )
    }

    private fun archivePackageInfo(file: File): PackageInfo? {
        val signingFlag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS or
            signingFlag
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageArchiveInfo(file.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageArchiveInfo(file.absolutePath, flags)
        }
    }

    private fun manifestSignals(packageInfo: PackageInfo): Set<ApkRiskSignal> {
        val signals = linkedSetOf<ApkRiskSignal>()
        val permissions = packageInfo.requestedPermissions?.toSet().orEmpty()

        if (Manifest.permission.SYSTEM_ALERT_WINDOW in permissions) signals += ApkRiskSignal.OVERLAY_PERMISSION
        if (Manifest.permission.REQUEST_INSTALL_PACKAGES in permissions) signals += ApkRiskSignal.REQUEST_INSTALL_PACKAGES
        if (permissions.any { it in SMS_PERMISSIONS }) signals += ApkRiskSignal.SMS_ACCESS
        if (Manifest.permission.READ_CONTACTS in permissions) signals += ApkRiskSignal.CONTACTS_ACCESS
        if (permissions.any { it in CALL_LOG_PERMISSIONS }) signals += ApkRiskSignal.CALL_LOG_ACCESS
        if (Manifest.permission.RECORD_AUDIO in permissions) signals += ApkRiskSignal.MICROPHONE
        if (Manifest.permission.CAMERA in permissions) signals += ApkRiskSignal.CAMERA
        if (Manifest.permission.ACCESS_FINE_LOCATION in permissions) signals += ApkRiskSignal.PRECISE_LOCATION
        if (Manifest.permission.RECEIVE_BOOT_COMPLETED in permissions) signals += ApkRiskSignal.BOOT_START
        if (Manifest.permission.QUERY_ALL_PACKAGES in permissions) signals += ApkRiskSignal.QUERY_ALL_PACKAGES

        if (packageInfo.services?.any { it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE } == true) {
            signals += ApkRiskSignal.ACCESSIBILITY_SERVICE
        }
        if (packageInfo.services?.any { it.permission == Manifest.permission.BIND_NOTIFICATION_LISTENER_SERVICE } == true) {
            signals += ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE
        }
        if (packageInfo.services?.any { it.permission == Manifest.permission.BIND_VPN_SERVICE } == true) {
            signals += ApkRiskSignal.VPN_SERVICE
        }
        if (packageInfo.receivers?.any { it.permission == Manifest.permission.BIND_DEVICE_ADMIN } == true) {
            signals += ApkRiskSignal.DEVICE_ADMIN_RECEIVER
        }
        val flags = packageInfo.applicationInfo?.flags ?: 0
        if (flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) signals += ApkRiskSignal.DEBUGGABLE
        return signals
    }

    private fun inspectArchive(file: File): ArchiveSignals {
        ZipFile(file).use { zip ->
            var entryCount = 0
            var declaredUncompressed = 0L
            var nativeCount = 0
            val dexEntries = mutableListOf<java.util.zip.ZipEntry>()
            val enumeration = zip.entries()
            while (enumeration.hasMoreElements()) {
                val entry = enumeration.nextElement()
                entryCount += 1
                if (entryCount > MAX_ZIP_ENTRIES) throw SizeLimitExceeded()
                if (entry.size > 0) {
                    declaredUncompressed += entry.size
                    if (declaredUncompressed > MAX_DECLARED_UNCOMPRESSED_BYTES) throw SizeLimitExceeded()
                }
                if (DEX_NAME.matches(entry.name.substringAfterLast('/'))) dexEntries += entry
                if (entry.name.startsWith("lib/") && entry.name.endsWith(".so")) nativeCount += 1
            }
            val signals = linkedSetOf<ApkRiskSignal>()
            if (nativeCount > 0) signals += ApkRiskSignal.NATIVE_CODE
            if (dexEntries.size >= MANY_DEX_THRESHOLD) signals += ApkRiskSignal.MANY_DEX_FILES

            var remainingCodeBytes = MAX_DEX_SCAN_BYTES
            var truncated = false
            for (entry in dexEntries) {
                if (remainingCodeBytes <= 0L) {
                    truncated = true
                    break
                }
                val scan = zip.getInputStream(entry).use { input -> scanDex(input, remainingCodeBytes) }
                remainingCodeBytes -= scan.bytesRead
                signals += scan.signals
                if (scan.truncated) {
                    truncated = true
                    break
                }
            }

            return ArchiveSignals(
                dexFileCount = dexEntries.size,
                nativeLibraryCount = nativeCount,
                signals = signals,
                codeScanTruncated = truncated
            )
        }
    }

    private fun scanDex(input: InputStream, maxBytes: Long): DexScan {
        val targets = DEX_MARKERS.keys.associateWith { it.toByteArray(Charsets.US_ASCII) }
        val found = linkedSetOf<ApkRiskSignal>()
        val maxNeedle = targets.values.maxOf { it.size }
        val buffer = ByteArray(32 * 1024)
        var carry = ByteArray(0)
        var total = 0L
        var truncated = false

        while (found.size < DEX_MARKERS.size) {
            if (total >= maxBytes) {
                truncated = true
                break
            }
            val allowed = minOf(buffer.size.toLong(), maxBytes - total).toInt()
            val read = input.read(buffer, 0, allowed)
            if (read < 0) break
            total += read

            val combined = ByteArray(carry.size + read)
            carry.copyInto(combined, 0)
            buffer.copyInto(combined, carry.size, 0, read)
            targets.forEach { (text, bytes) ->
                if (DEX_MARKERS.getValue(text) !in found && containsBytes(combined, bytes)) {
                    found += DEX_MARKERS.getValue(text)
                }
            }
            val keep = minOf(maxNeedle - 1, combined.size)
            carry = combined.copyOfRange(combined.size - keep, combined.size)
        }
        return DexScan(total, found, truncated)
    }

    private fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    private fun copyBounded(uri: Uri, destination: File): String? {
        val digest = MessageDigest.getInstance("SHA-256")
        val input = resolver.openInputStream(uri) ?: return null
        input.use { source ->
            FileOutputStream(destination).use { output ->
                val buffer = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val read = source.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > MAX_APK_BYTES) throw SizeLimitExceeded()
                    digest.update(buffer, 0, read)
                    output.write(buffer, 0, read)
                }
                output.fd.sync()
            }
        }
        return digest.digest().toHex()
    }

    private fun signingCertificateSha256(packageInfo: PackageInfo): String? {
        val signer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = packageInfo.signingInfo ?: return null
            val signers = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
            signers.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures?.firstOrNull()?.toByteArray()
        } ?: return null
        return MessageDigest.getInstance("SHA-256").digest(signer).toHex()
    }

    private fun selectIdentityIndicator(
        signer: ApkIdentityIndicator?,
        packageName: ApkIdentityIndicator?
    ): ApkIdentityIndicator? {
        val values = listOfNotNull(signer, packageName)
        return values.firstOrNull { it.classification == ApkIdentityClassification.KNOWN_THREAT }
            ?: values.firstOrNull()
    }

    private fun sha256Text(value: String): String =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).toHex()

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte -> "%02x".format(byte) }

    private data class ArchiveSignals(
        val dexFileCount: Int,
        val nativeLibraryCount: Int,
        val signals: Set<ApkRiskSignal>,
        val codeScanTruncated: Boolean
    )

    private data class DexScan(
        val bytesRead: Long,
        val signals: Set<ApkRiskSignal>,
        val truncated: Boolean
    )

    private class SizeLimitExceeded : Exception()

    companion object {
        private const val MAX_APK_BYTES = 512L * 1024L * 1024L
        private const val MAX_DECLARED_UNCOMPRESSED_BYTES = 2L * 1024L * 1024L * 1024L
        private const val MAX_ZIP_ENTRIES = 20_000
        private const val MAX_DEX_SCAN_BYTES = 64L * 1024L * 1024L
        private const val MANY_DEX_THRESHOLD = 8
        private val DEX_NAME = Regex("classes(?:[0-9]+)?\\.dex", RegexOption.IGNORE_CASE)

        private val SMS_PERMISSIONS = setOf(
            Manifest.permission.READ_SMS,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.SEND_SMS
        )
        private val CALL_LOG_PERMISSIONS = setOf(
            Manifest.permission.READ_CALL_LOG,
            Manifest.permission.WRITE_CALL_LOG
        )
        private val DEX_MARKERS = linkedMapOf(
            "Ldalvik/system/DexClassLoader;" to ApkRiskSignal.DYNAMIC_CODE_LOADING,
            "Ljava/lang/Runtime;" to ApkRiskSignal.RUNTIME_EXECUTION,
            "Landroid/telephony/SmsManager;" to ApkRiskSignal.SMS_API,
            "getDeviceId" to ApkRiskSignal.DEVICE_IDENTIFIER_API
        )
    }
}
