package com.aman.security.security

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.aman.security.scanner.ScanResult
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.UUID

class QuarantineManager(
    private val context: Context,
    private val store: SecurityRecordStore,
    private val crypto: QuarantineCrypto = QuarantineCrypto()
) {
    sealed interface QuarantineResult {
        data class Success(val entry: QuarantineEntry) : QuarantineResult
        data object SourceChanged : QuarantineResult
        data object SourceRemovalFailed : QuarantineResult
        data object Failed : QuarantineResult
    }

    sealed interface RestoreResult {
        data object Success : RestoreResult
        data object IntegrityFailed : RestoreResult
        data object Failed : RestoreResult
    }

    fun quarantine(uri: Uri, scan: ScanResult): QuarantineResult {
        val directory = File(context.filesDir, DIRECTORY).apply { mkdirs() }
        val id = UUID.randomUUID().toString()
        val blobName = "$id.aq"
        val blob = File(directory, blobName)
        val digest = MessageDigest.getInstance("SHA-256")

        try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(blob).use { output ->
                    crypto.encrypt(input, output) { bytes, count -> digest.update(bytes, 0, count) }
                }
            } ?: return QuarantineResult.Failed

            val encryptedPlainHash = digest.digest().toHex()
            if (!encryptedPlainHash.equals(scan.sha256, ignoreCase = true)) {
                blob.delete()
                return QuarantineResult.SourceChanged
            }

            val entry = QuarantineEntry(
                id = id,
                fileName = scan.fileName,
                sizeBytes = scan.sizeBytes,
                sha256 = scan.sha256.lowercase(),
                signatureId = scan.signatureId,
                classification = scan.classification,
                quarantinedAt = System.currentTimeMillis(),
                blobName = blobName
            )
            store.putQuarantine(entry)

            if (!deleteSource(context.contentResolver, uri)) {
                store.removeQuarantine(id)
                blob.delete()
                return QuarantineResult.SourceRemovalFailed
            }
            return QuarantineResult.Success(entry)
        } catch (_: Exception) {
            store.removeQuarantine(id)
            blob.delete()
            return QuarantineResult.Failed
        }
    }

    fun restore(id: String, destination: Uri): RestoreResult {
        val entry = store.findQuarantine(id) ?: return RestoreResult.Failed
        val blob = File(File(context.filesDir, DIRECTORY), entry.blobName)
        if (!blob.isFile) return RestoreResult.Failed
        val digest = MessageDigest.getInstance("SHA-256")

        return try {
            context.contentResolver.openOutputStream(destination, "w")?.use { output ->
                FileInputStream(blob).use { input ->
                    crypto.decrypt(input, output) { bytes, count -> digest.update(bytes, 0, count) }
                }
            } ?: return RestoreResult.Failed
            val restoredHash = digest.digest().toHex()
            if (!restoredHash.equals(entry.sha256, ignoreCase = true)) {
                runCatching { deleteSource(context.contentResolver, destination) }
                RestoreResult.IntegrityFailed
            } else {
                blob.delete()
                store.removeQuarantine(id)
                RestoreResult.Success
            }
        } catch (_: Exception) {
            RestoreResult.Failed
        }
    }

    fun deletePermanently(id: String): Boolean {
        val entry = store.findQuarantine(id) ?: return false
        val blob = File(File(context.filesDir, DIRECTORY), entry.blobName)
        val deleted = !blob.exists() || blob.delete()
        if (deleted) store.removeQuarantine(id)
        return deleted
    }

    private fun deleteSource(resolver: ContentResolver, uri: Uri): Boolean = runCatching {
        if (DocumentsContract.isDocumentUri(context, uri)) {
            DocumentsContract.deleteDocument(resolver, uri)
        } else {
            resolver.delete(uri, null, null) > 0
        }
    }.getOrDefault(false)

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    companion object {
        private const val DIRECTORY = "quarantine_v1"
    }
}
