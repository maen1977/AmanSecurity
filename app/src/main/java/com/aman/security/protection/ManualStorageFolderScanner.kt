package com.aman.security.protection

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.ScanClassification
import com.aman.security.security.SecurityRecordStore
import java.util.ArrayDeque
import java.util.concurrent.CancellationException

enum class ManualStorageScanMode {
    QUICK,
    FULL
}

data class ManualStorageScanLimits(
    val maxDocuments: Int,
    val maxScanFiles: Int,
    val maxTreeDepth: Int
)

/**
 * Foreground-only scan of a user-selected SAF tree. It deliberately does not
 * become a background service and never mutates or deletes user files.
 */
class ManualStorageFolderScanner(
    private val resolver: ContentResolver,
    private val fileScanner: FileScanner,
    private val eventStore: ProtectionEventStore,
    private val recordStore: SecurityRecordStore,
    private val notifier: (ProtectionEvent) -> Unit,
    private val cache: ManualStorageScanCache? = null,
    private val databaseVersion: String = ""
) {
    fun scan(
        treeUri: Uri,
        mode: ManualStorageScanMode = ManualStorageScanMode.FULL,
        onProgress: ((scannedFiles: Int, fileName: String) -> Unit)? = null,
        shouldCancel: (() -> Boolean)? = null
    ): ManualStorageScanSummary {
        val limits = ProtectionPolicy.storageLimits(mode)
        if (!hasPersistedReadPermission(treeUri)) {
            return ManualStorageScanSummary(mode = mode, permissionLost = true)
        }

        val rootId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull()
            ?: return ManualStorageScanSummary(mode = mode, permissionLost = true)
        val queue = ArrayDeque<Node>()
        queue.add(Node(rootId, 0))

        var visited = 0
        var scanned = 0
        var reused = 0
        var skipped = 0
        var inaccessible = 0
        var alerts = 0
        var known = 0
        var high = 0
        var truncated = false
        val findings = mutableListOf<ManualStorageAlertFinding>()

        while (queue.isNotEmpty()) {
            if (shouldCancel?.invoke() == true) throw CancellationException("storage scan cancelled")
            if (visited >= limits.maxDocuments || scanned >= limits.maxScanFiles) {
                truncated = true
                break
            }

            val node = queue.removeFirst()
            if (node.depth > limits.maxTreeDepth) continue
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
                    if (shouldCancel?.invoke() == true) throw CancellationException("storage scan cancelled")
                    if (visited >= limits.maxDocuments || scanned >= limits.maxScanFiles) {
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
                    val lastModified = if (modifiedIndex >= 0 && !it.isNull(modifiedIndex)) {
                        it.getLong(modifiedIndex)
                    } else {
                        -1L
                    }
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
                    val cached = cache?.get(
                        treeUri = treeUri.toString(),
                        documentId = documentId,
                        sizeBytes = size,
                        lastModified = lastModified,
                        databaseVersion = databaseVersion
                    )
                    if (cached != null) {
                        scanned++
                        reused++
                        onProgress?.invoke(scanned, cached.fileName.ifBlank { fileName })
                        val excluded = recordStore.isExcluded(cached.sha256)
                        val severity = cached.severity
                        if (severity != null && !excluded) {
                            val event = eventStore.add(
                                type = ProtectionEventType.FILE,
                                displayName = cached.fileName.ifBlank { fileName },
                                detail = cached.sha256,
                                severity = severity
                            )
                            notifier(event)
                            alerts++
                            if (severity == ProtectionSeverity.KNOWN_THREAT) known++ else high++
                            findings += ManualStorageAlertFinding(
                                displayName = cached.fileName.ifBlank { fileName },
                                location = documentUri.toString(),
                                sha256 = cached.sha256,
                                severity = severity
                            )
                        }
                        continue
                    }

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
                    cache?.put(
                        treeUri = treeUri.toString(),
                        documentId = documentId,
                        sizeBytes = size,
                        lastModified = lastModified,
                        databaseVersion = databaseVersion,
                        fileName = result.fileName,
                        sha256 = result.sha256,
                        severity = severity
                    )
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
                                severity = severity,
                                archiveEntryName = result.archiveFinding?.entryName
                            )
                    }
                }
            }
        }

        return ManualStorageScanSummary(
            mode = mode,
            scannedFiles = scanned,
            reusedFiles = reused,
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
            DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED
        )
    }
}

data class ManualStorageScanSummary(
    val mode: ManualStorageScanMode = ManualStorageScanMode.FULL,
    val scannedFiles: Int = 0,
    val reusedFiles: Int = 0,
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
    val severity: ProtectionSeverity,
    val archiveEntryName: String? = null
)
