package com.aman.security.protection

import android.content.SharedPreferences
import java.security.MessageDigest

/**
 * Small metadata cache for the user-initiated storage scan. It never stores file
 * contents; entries are reusable only when size, modification time, and threat
 * database serial are unchanged.
 */
class ManualStorageScanCache(
    private val preferences: SharedPreferences
) {
    fun get(
        treeUri: String,
        documentId: String,
        sizeBytes: Long,
        lastModified: Long,
        databaseVersion: String
    ): Entry? {
        if (sizeBytes < 0L || lastModified < 0L) return null
        val key = entryKey(treeUri, documentId)
        if (preferences.getString(field(key, "db"), null) != databaseVersion) return null
        if (preferences.getLong(field(key, "size"), Long.MIN_VALUE) != sizeBytes) return null
        if (preferences.getLong(field(key, "modified"), Long.MIN_VALUE) != lastModified) return null
        val sha256 = preferences.getString(field(key, "sha256"), null) ?: return null
        val fileName = preferences.getString(field(key, "name"), null).orEmpty()
        val severity = preferences.getString(field(key, "severity"), null)
            ?.takeUnless { it == NONE }
            ?.let { runCatching { ProtectionSeverity.valueOf(it) }.getOrNull() }
        return Entry(fileName = fileName, sha256 = sha256, severity = severity)
    }

    fun put(
        treeUri: String,
        documentId: String,
        sizeBytes: Long,
        lastModified: Long,
        databaseVersion: String,
        fileName: String,
        sha256: String,
        severity: ProtectionSeverity?
    ) {
        if (sizeBytes < 0L || lastModified < 0L) return
        val key = entryKey(treeUri, documentId)
        preferences.edit()
            .putString(field(key, "db"), databaseVersion)
            .putLong(field(key, "size"), sizeBytes)
            .putLong(field(key, "modified"), lastModified)
            .putString(field(key, "name"), fileName)
            .putString(field(key, "sha256"), sha256)
            .putString(field(key, "severity"), severity?.name ?: NONE)
            .putString(ORDER_KEY, updatedOrder(key).joinToString(ORDER_SEPARATOR))
            .apply()
        evictIfNeeded()
    }

    private fun updatedOrder(key: String): MutableList<String> {
        val current = preferences.getString(ORDER_KEY, null)
            ?.split(ORDER_SEPARATOR)
            ?.filter { it.isNotBlank() }
            ?.toMutableList()
            ?: mutableListOf()
        current.remove(key)
        current += key
        return current
    }

    private fun evictIfNeeded() {
        val order = preferences.getString(ORDER_KEY, null)
            ?.split(ORDER_SEPARATOR)
            ?.filter { it.isNotBlank() }
            ?.toMutableList()
            ?: return
        while (order.size > MAX_ENTRIES) {
            val oldest = order.removeAt(0)
            preferences.edit()
                .remove(field(oldest, "db"))
                .remove(field(oldest, "size"))
                .remove(field(oldest, "modified"))
                .remove(field(oldest, "name"))
                .remove(field(oldest, "sha256"))
                .remove(field(oldest, "severity"))
                .apply()
        }
        preferences.edit().putString(ORDER_KEY, order.joinToString(ORDER_SEPARATOR)).apply()
    }

    private fun entryKey(treeUri: String, documentId: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("$treeUri\u0000$documentId".toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun field(key: String, name: String): String = "$PREFIX$key:$name"

    data class Entry(
        val fileName: String,
        val sha256: String,
        val severity: ProtectionSeverity?
    )

    companion object {
        private const val PREFIX = "manual_scan_cache_"
        private const val ORDER_KEY = "manual_scan_cache_order"
        private const val ORDER_SEPARATOR = ","
        private const val MAX_ENTRIES = 512
        private const val NONE = "NONE"
    }
}
