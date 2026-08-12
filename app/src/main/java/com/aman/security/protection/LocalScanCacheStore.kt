package com.aman.security.protection

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Small on-device scan cache used to avoid re-reading unchanged APKs/files.
 * The cache never leaves the device. Metadata fingerprints are cheap to compute;
 * SHA-256 is reused only while that metadata and the bundled engine serial match.
 */
data class CachedAppArtifact(
    val packageName: String,
    val appName: String,
    val metadataFingerprint: String,
    val componentHashes: List<String>,
    val signerHashes: Set<String>,
    val lastSeenAt: Long
)

data class CachedFileArtifact(
    val key: String,
    val scope: String,
    val displayName: String,
    val location: String,
    val metadataFingerprint: String,
    val sha256: String,
    val lastSeenAt: Long
)

class LocalScanCacheStore(context: Context) {
    private val directory = File(context.filesDir, DIRECTORY).apply { mkdirs() }
    private val appsFile = File(directory, "apps.json")
    private val filesFile = File(directory, "files.json")

    fun loadApps(): MutableMap<String, CachedAppArtifact> = synchronized(LOCK) { loadAppsUnlocked() }

    fun saveApps(entries: Map<String, CachedAppArtifact>) = synchronized(LOCK) {
        // Merge with disk so a long-lived UI scanner cannot erase entries written by a worker.
        val merged = loadAppsUnlocked().apply { putAll(entries) }
        val bounded = merged.values.sortedByDescending { it.lastSeenAt }.take(MAX_APPS)
        val array = JSONArray()
        bounded.forEach { entry ->
            array.put(
                JSONObject()
                    .put("packageName", entry.packageName)
                    .put("appName", entry.appName)
                    .put("metadataFingerprint", entry.metadataFingerprint)
                    .put("componentHashes", JSONArray(entry.componentHashes.distinct()))
                    .put("signerHashes", JSONArray(entry.signerHashes.toList()))
                    .put("lastSeenAt", entry.lastSeenAt)
            )
        }
        atomicWrite(appsFile, array.toString().toByteArray(Charsets.UTF_8))
    }

    fun loadFiles(): MutableMap<String, CachedFileArtifact> = synchronized(LOCK) { loadFilesUnlocked() }

    fun saveFiles(entries: Map<String, CachedFileArtifact>) = synchronized(LOCK) {
        val merged = loadFilesUnlocked().apply { putAll(entries) }
        val bounded = merged.values.sortedByDescending { it.lastSeenAt }.take(MAX_FILES)
        val array = JSONArray()
        bounded.forEach { entry ->
            array.put(
                JSONObject()
                    .put("key", entry.key)
                    .put("scope", entry.scope)
                    .put("displayName", entry.displayName)
                    .put("location", entry.location)
                    .put("metadataFingerprint", entry.metadataFingerprint)
                    .put("sha256", entry.sha256)
                    .put("lastSeenAt", entry.lastSeenAt)
            )
        }
        atomicWrite(filesFile, array.toString().toByteArray(Charsets.UTF_8))
    }

    private fun loadAppsUnlocked(): MutableMap<String, CachedAppArtifact> {
        val array = readArray(appsFile)
        val result = linkedMapOf<String, CachedAppArtifact>()
        for (index in 0 until array.length()) {
            val json = array.optJSONObject(index) ?: continue
            val entry = runCatching {
                CachedAppArtifact(
                    packageName = json.getString("packageName"),
                    appName = json.optString("appName").ifBlank { json.getString("packageName") },
                    metadataFingerprint = json.getString("metadataFingerprint"),
                    componentHashes = json.optJSONArray("componentHashes").toStringList().filter(::isSha256),
                    signerHashes = json.optJSONArray("signerHashes").toStringList().filter(::isSha256).toCollection(linkedSetOf()),
                    lastSeenAt = json.optLong("lastSeenAt", 0L)
                )
            }.getOrNull() ?: continue
            if (entry.componentHashes.isNotEmpty()) result[entry.packageName] = entry
        }
        return result
    }

    private fun loadFilesUnlocked(): MutableMap<String, CachedFileArtifact> {
        val array = readArray(filesFile)
        val result = linkedMapOf<String, CachedFileArtifact>()
        for (index in 0 until array.length()) {
            val json = array.optJSONObject(index) ?: continue
            val entry = runCatching {
                CachedFileArtifact(
                    key = json.getString("key"),
                    scope = json.getString("scope"),
                    displayName = json.optString("displayName").ifBlank { "—" },
                    location = json.optString("location"),
                    metadataFingerprint = json.getString("metadataFingerprint"),
                    sha256 = json.getString("sha256").lowercase(),
                    lastSeenAt = json.optLong("lastSeenAt", 0L)
                )
            }.getOrNull() ?: continue
            if (isSha256(entry.sha256)) result[entry.key] = entry
        }
        return result
    }

    private fun readArray(file: File): JSONArray = runCatching {
        if (!file.isFile) JSONArray() else JSONArray(file.readText(Charsets.UTF_8))
    }.getOrDefault(JSONArray())

    private fun JSONArray?.toStringList(): List<String> {
        if (this == null) return emptyList()
        return buildList {
            for (index in 0 until length()) {
                optString(index).takeIf { it.isNotBlank() }?.let(::add)
            }
        }
    }

    private fun atomicWrite(target: File, bytes: ByteArray) {
        val temp = File(target.parentFile, target.name + ".tmp")
        temp.writeBytes(bytes)
        if (!temp.renameTo(target)) {
            target.writeBytes(bytes)
            temp.delete()
        }
    }

    companion object {
        const val SCOPE_DOWNLOADS = "downloads"
        const val SCOPE_PROTECTED_FOLDER = "protected_folder"
        private const val DIRECTORY = "local-scan-cache-v1"
        private const val MAX_APPS = 2000
        private const val MAX_FILES = 7000
        private val SHA256 = Regex("^[a-f0-9]{64}$")
        private val LOCK = Any()
        private fun isSha256(value: String): Boolean = SHA256.matches(value.lowercase())
    }
}
