package com.aman.security.protection

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.ScanClassification
import com.aman.security.security.SecurityRecordStore
import java.util.ArrayDeque

class ProtectedFolderScanner(
    private val resolver: ContentResolver,
    private val fileScanner: FileScanner,
    private val preferences: ProtectionPreferences,
    private val eventStore: ProtectionEventStore,
    private val recordStore: SecurityRecordStore,
    private val notifier: (ProtectionEvent) -> Unit
) {
    fun scan(treeUri: Uri): ProtectedFolderScanSummary {
        if (!hasPersistedReadPermission(treeUri)) {
            preferences.folderPermissionLost = true
            preferences.lastCheckAt = System.currentTimeMillis()
            return ProtectedFolderScanSummary(0, 0, 0, 0, 0, 0, false, true)
        }

        val ledger = preferences.ledger()
        val queue = ArrayDeque<Node>()
        val rootId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull()
            ?: return permissionFailure()
        queue.add(Node(rootId, 0))

        var visited = 0
        var scanned = 0
        var skipped = 0
        var alerts = 0
        var known = 0
        var high = 0
        var inaccessible = 0
        var truncated = false

        while (queue.isNotEmpty()) {
            if (visited >= ProtectionPolicy.MAX_DOCUMENTS_PER_RUN || scanned >= ProtectionPolicy.MAX_SCAN_FILES_PER_RUN) {
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
                val modifiedIndex = it.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)

                while (it.moveToNext()) {
                    if (visited >= ProtectionPolicy.MAX_DOCUMENTS_PER_RUN || scanned >= ProtectionPolicy.MAX_SCAN_FILES_PER_RUN) {
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
                    val modified = if (modifiedIndex >= 0 && !it.isNull(modifiedIndex)) it.getLong(modifiedIndex) else -1L
                    if (!ProtectionPolicy.shouldScanFile(fileName, size)) continue

                    val ledgerKey = preferences.ledgerKey(documentId)
                    val fingerprint = "$size:$modified"
                    if (ledger[ledgerKey] == fingerprint) {
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

                    val resultOutcome = runCatching { fileScanner.scan(documentUri) }
                    if (resultOutcome.isFailure) {
                        inaccessible++
                        continue
                    }
                    val result = resultOutcome.getOrThrow()
                    scanned++
                    ledger[ledgerKey] = fingerprint

                    if (result.classification == ScanClassification.KNOWN_THREAT ||
                        result.classification == ScanClassification.SUSPICIOUS
                    ) {
                        recordStore.recordScan(result)
                    }

                    val excluded = recordStore.isExcluded(result.sha256)
                    if (ProtectionPolicy.shouldNotifyFile(result, excluded)) {
                        val severity = ProtectionPolicy.severityForFile(result) ?: continue
                        val event = eventStore.add(
                            type = ProtectionEventType.FILE,
                            displayName = result.fileName,
                            detail = result.sha256,
                            severity = severity
                        )
                        notifier(event)
                        alerts++
                        if (severity == ProtectionSeverity.KNOWN_THREAT) known++ else high++
                    }
                }
            }
        }

        preferences.saveLedger(ledger)
        preferences.folderPermissionLost = false
        preferences.lastCheckAt = System.currentTimeMillis()
        preferences.lastScannedCount = scanned
        preferences.lastAlertCount = alerts
        return ProtectedFolderScanSummary(scanned, skipped, alerts, known, high, inaccessible, truncated, false)
    }

    private fun hasPersistedReadPermission(treeUri: Uri): Boolean =
        resolver.persistedUriPermissions.any { permission ->
            permission.uri == treeUri && permission.isReadPermission
        }

    private fun permissionFailure(): ProtectedFolderScanSummary {
        preferences.folderPermissionLost = true
        preferences.lastCheckAt = System.currentTimeMillis()
        return ProtectedFolderScanSummary(0, 0, 0, 0, 0, 0, false, true)
    }

    private data class Node(val documentId: String, val depth: Int)

    companion object {
        private val PROJECTION = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED
        )
    }
}
