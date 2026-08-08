package com.aman.security.security

import android.content.Context
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.ScanResult
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

class SecurityRecordStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    @Synchronized
    fun quarantineEntries(): List<QuarantineEntry> = readArray(KEY_QUARANTINE).mapNotNull(::quarantineFromJson)
        .sortedByDescending { it.quarantinedAt }

    @Synchronized
    fun findQuarantine(id: String): QuarantineEntry? = quarantineEntries().firstOrNull { it.id == id }

    @Synchronized
    fun putQuarantine(entry: QuarantineEntry) {
        val entries = quarantineEntries().filterNot { it.id == entry.id }.toMutableList()
        entries += entry
        writeArray(KEY_QUARANTINE, entries.map(::quarantineToJson))
    }

    @Synchronized
    fun removeQuarantine(id: String) {
        writeArray(KEY_QUARANTINE, quarantineEntries().filterNot { it.id == id }.map(::quarantineToJson))
    }

    @Synchronized
    fun exclusions(): List<ExclusionEntry> = readArray(KEY_EXCLUSIONS).mapNotNull(::exclusionFromJson)
        .sortedByDescending { it.addedAt }

    @Synchronized
    fun isExcluded(sha256: String): Boolean = exclusions().any { it.sha256.equals(sha256, ignoreCase = true) }

    @Synchronized
    fun addExclusion(result: ScanResult) {
        val normalized = result.sha256.lowercase()
        val entries = exclusions().filterNot { it.sha256.equals(normalized, ignoreCase = true) }.toMutableList()
        entries += ExclusionEntry(normalized, result.fileName, System.currentTimeMillis())
        writeArray(KEY_EXCLUSIONS, entries.map(::exclusionToJson))
    }

    @Synchronized
    fun removeExclusion(sha256: String) {
        writeArray(KEY_EXCLUSIONS, exclusions().filterNot { it.sha256.equals(sha256, ignoreCase = true) }.map(::exclusionToJson))
    }

    @Synchronized
    fun history(): List<ScanHistoryEntry> = readArray(KEY_HISTORY).mapNotNull(::historyFromJson)
        .sortedByDescending { it.scannedAt }

    @Synchronized
    fun recordScan(result: ScanResult) {
        val entries = history().toMutableList()
        entries.add(
            0,
            ScanHistoryEntry(
                id = UUID.randomUUID().toString(),
                fileName = result.fileName,
                sha256 = result.sha256.lowercase(),
                classification = result.classification,
                scannedAt = System.currentTimeMillis()
            )
        )
        writeArray(KEY_HISTORY, entries.take(MAX_HISTORY).map(::historyToJson))
    }

    @Synchronized
    fun clearHistory() = prefs.edit().remove(KEY_HISTORY).apply()

    private fun readArray(key: String): List<JSONObject> {
        val raw = prefs.getString(key, null) ?: return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { index -> array.optJSONObject(index) }
        }.getOrDefault(emptyList())
    }

    private fun writeArray(key: String, values: List<JSONObject>) {
        val array = JSONArray()
        values.forEach(array::put)
        prefs.edit().putString(key, array.toString()).apply()
    }

    private fun quarantineToJson(entry: QuarantineEntry) = JSONObject()
        .put("id", entry.id)
        .put("fileName", entry.fileName)
        .put("sizeBytes", entry.sizeBytes)
        .put("sha256", entry.sha256)
        .put("signatureId", entry.signatureId ?: JSONObject.NULL)
        .put("classification", entry.classification.name)
        .put("quarantinedAt", entry.quarantinedAt)
        .put("blobName", entry.blobName)

    private fun quarantineFromJson(json: JSONObject): QuarantineEntry? = runCatching {
        QuarantineEntry(
            id = json.getString("id"),
            fileName = json.getString("fileName"),
            sizeBytes = json.optLong("sizeBytes", -1L),
            sha256 = json.getString("sha256"),
            signatureId = json.optString("signatureId").takeIf { it.isNotBlank() && it != "null" },
            classification = ScanClassification.valueOf(json.getString("classification")),
            quarantinedAt = json.getLong("quarantinedAt"),
            blobName = json.getString("blobName")
        )
    }.getOrNull()

    private fun exclusionToJson(entry: ExclusionEntry) = JSONObject()
        .put("sha256", entry.sha256)
        .put("fileName", entry.fileName)
        .put("addedAt", entry.addedAt)

    private fun exclusionFromJson(json: JSONObject): ExclusionEntry? = runCatching {
        ExclusionEntry(
            sha256 = json.getString("sha256"),
            fileName = json.getString("fileName"),
            addedAt = json.getLong("addedAt")
        )
    }.getOrNull()

    private fun historyToJson(entry: ScanHistoryEntry) = JSONObject()
        .put("id", entry.id)
        .put("fileName", entry.fileName)
        .put("sha256", entry.sha256)
        .put("classification", entry.classification.name)
        .put("scannedAt", entry.scannedAt)

    private fun historyFromJson(json: JSONObject): ScanHistoryEntry? = runCatching {
        ScanHistoryEntry(
            id = json.getString("id"),
            fileName = json.getString("fileName"),
            sha256 = json.getString("sha256"),
            classification = ScanClassification.valueOf(json.getString("classification")),
            scannedAt = json.getLong("scannedAt")
        )
    }.getOrNull()

    companion object {
        private const val PREFS_NAME = "security_records_v1"
        private const val KEY_QUARANTINE = "quarantine_entries"
        private const val KEY_EXCLUSIONS = "exclusions"
        private const val KEY_HISTORY = "scan_history"
        private const val MAX_HISTORY = 100
    }
}
