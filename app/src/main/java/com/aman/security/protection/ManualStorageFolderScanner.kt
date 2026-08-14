package com.aman.security.protection

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.ScanClassification
import com.aman.security.security.SecurityRecordStore
import java.util.ArrayDeque
import java.util.concurrent.CancellationException

/**
 * Foreground-only scan of a user-selected SAF tree. It deliberately does not
 * become a background service and never mutates or deletes user files.
 */
class ManualStorageFolderScanner(
    private val resolver: ContentResolver,
    private val fileScanner: FileScanner,
    private val eventStore: ProtectionEventStore,
    private val recordStore: SecurityRecordStore,
    private val notifier: (ProtectionEvent) -> Unit
) {
    fun scan(
        treeUri: Uri,
        onProgress: ((scannedFiles: Int, fileName: String) -> Unit)? = null,
        shouldCancel: (() -> Boolean)? = null
    ): ManualStorageScanSummary {
        if (!hasPersistedReadPermission(treeUri)) {
            return ManualStorageScanSummary(permissionLost = true)
        }

        val rootId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull()
            ?: return ManualStorageScanSummary(permissionLost = true)
        val queue = ArrayDeque<Node>()
        queue.add(Node(rootId, 0))

        var visited = 0
        var scanned = 0
        var skipped = 0
        var inaccessible = 0
        var alerts = 0
        var known = 0
        var high = 0
        var truncated = false
        val findings = mutableListOf<ManualStorageAlertFinding>()

        while (queue.isNotEmpty()) {
            if (shouldCancel?.invoke() == true) throw CancellationException("storage scan cancelled")
            if (visited >= ProtectionPolicy.MAX_DOCUMENTS_PER_RUN ||
                scanned >= ProtectionPolicy.MAX_SCAN_FILES_PER_RUN
            ) {
                truncated = true
                break
            }

            val node = queue.removeFirst()
            if (node.depth > ProtectionPolicy.MAX_TREE_DEPTH) continue
            val childrenUri = runCatching {
                DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, node.documentId)
            }.getOrNull() ?: continue
            val cursor = runCatching {
                resolver.query(childrenUri, PROJECTION, null, null, null)
            }.getOrNull()
            if (cursor == null) {
                inaccessible++
                continue
            }

            cursor.use {
                val idIndex = it.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val nameIndex = it.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val mimeIndex = it.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                val sizeIndex = it.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)

                while (it.moveToNext()) {
                    if (shouldCancel?.invoke() == true) throw CancellationException("storage scan cancelled")
                    if (visited >= ProtectionPolicy.MAX_DOCUMENTS_PER_RUN ||
                        scanned >= ProtectionPolicy.MAX_SCAN_FILES_PER_RUN
                    ) {
                        truncated = true
                        break
                    }
                    visited++
                    val documentId = if (idIndex >= 0) it.getString(idIndex) else null
                    if (documentId.isNullOrBlank()) continue
                    val mimeType = if (mimeIndex >= 0) it.getString(mimeIndex) else null
                    if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                        queue.add(Node(documentId, node.depth + 1))
                        continue
                    }

                    val fileName = if (nameIndex >= 0) it.getString(nameIndex).orEmpty() else ""
                    val size = if (sizeIndex >= 0 && !it.isNull(sizeIndex)) it.getLong(sizeIndex) else -1L
                    if (!ProtectionPolicy.shouldScanFile(fileName, size)) {
                        skipped++
                        continue
                    }

                    val documentUri = runCatching {
                        DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
                    }.getOrNull()
                    if (documentUri == null) {
                        inaccessible++
                        continue
                    }

                    onProgress?.invoke(scanned, fileName)
                    val result = runCatching { fileScanner.scan(documentUri) }.getOrNull()
                    if (result == null) {
                        inaccessible++
                        continue
                    }
                    scanned++
                    onProgress?.invoke(scanned, fileName)

                    if (result.classification == ScanClassification.KNOWN_THREAT ||
                        result.classification == ScanClassification.SUSPICIOUS
                    ) {
                        recordStore.recordScan(result)
                    }

                    val excluded = recordStore.isExcluded(result.sha256)
                    val severity = ProtectionPolicy.severityForFile(result)
                    if (severity != null && !excluded) {
                        val event = eventStore.add(
                            type = ProtectionEventType.FILE,
                            displayName = result.fileName,
                            detail = result.sha256,
                            severity = severity
                        )
                        notifier(event)
                        alerts++
                        if (severity == ProtectionSeverity.KNOWN_THREAT) known++ else high++
                        findings += ManualStorageAlertFinding(
                            displayName = result.fileName,
                            location = documentUri.toString(),
                            sha256 = result.sha256,
                            severity = severity
                        )
                    }
                }
            }
        }

        return ManualStorageScanSummary(
            scannedFiles = scanned,
            alerts = alerts,
            knownThreats = known,
            highRisk = high,
            skippedFiles = skipped,
            inaccessibleFiles = inaccessible,
            truncated = truncated,
            permissionLost = false,
            findings = findings
        )
    }

    private fun hasPersistedReadPermission(treeUri: Uri): Boolean =
        resolver.persistedUriPermissions.any { permission ->
            permission.uri == treeUri && permission.isReadPermission
        }

    private data class Node(val documentId: String, val depth: Int)

    companion object {
        private val PROJECTION = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE
        )
    }
}

data class ManualStorageScanSummary(
    val scannedFiles: Int = 0,
    val alerts: Int = 0,
    val knownThreats: Int = 0,
    val highRisk: Int = 0,
    val skippedFiles: Int = 0,
    val inaccessibleFiles: Int = 0,
    val truncated: Boolean = false,
    val permissionLost: Boolean = false,
    val findings: List<ManualStorageAlertFinding> = emptyList()
)

data class ManualStorageAlertFinding(
    val displayName: String,
    val location: String,
    val sha256: String,
    val severity: ProtectionSeverity
)
