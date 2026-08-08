package com.aman.security.protection

import android.content.Context
import android.net.Uri
import org.json.JSONObject
import java.security.MessageDigest

class ProtectionPreferences(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var enabled: Boolean
        get() = prefs.getBoolean(KEY_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_ENABLED, value).apply()

    var protectedTreeUri: Uri?
        get() = prefs.getString(KEY_TREE_URI, null)?.let(Uri::parse)
        set(value) = prefs.edit().putString(KEY_TREE_URI, value?.toString()).apply()

    var lastCheckAt: Long
        get() = prefs.getLong(KEY_LAST_CHECK_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_CHECK_AT, value).apply()

    var lastScannedCount: Int
        get() = prefs.getInt(KEY_LAST_SCANNED_COUNT, 0)
        set(value) = prefs.edit().putInt(KEY_LAST_SCANNED_COUNT, value).apply()

    var lastAlertCount: Int
        get() = prefs.getInt(KEY_LAST_ALERT_COUNT, 0)
        set(value) = prefs.edit().putInt(KEY_LAST_ALERT_COUNT, value).apply()

    var folderPermissionLost: Boolean
        get() = prefs.getBoolean(KEY_PERMISSION_LOST, false)
        set(value) = prefs.edit().putBoolean(KEY_PERMISSION_LOST, value).apply()

    @Synchronized
    fun ledger(): MutableMap<String, String> {
        val raw = prefs.getString(KEY_LEDGER, null) ?: return linkedMapOf()
        return runCatching {
            val json = JSONObject(raw)
            val result = linkedMapOf<String, String>()
            json.keys().forEach { key -> result[key] = json.optString(key) }
            result
        }.getOrDefault(linkedMapOf())
    }

    @Synchronized
    fun saveLedger(values: Map<String, String>) {
        val bounded = values.entries.toList().takeLast(MAX_LEDGER_ENTRIES)
        val json = JSONObject()
        bounded.forEach { (key, value) -> json.put(key, value) }
        prefs.edit().putString(KEY_LEDGER, json.toString()).apply()
    }

    fun clearLedger() = prefs.edit().remove(KEY_LEDGER).apply()

    fun ledgerKey(documentId: String): String = MessageDigest.getInstance("SHA-256")
        .digest(documentId.toByteArray(Charsets.UTF_8))
        .joinToString(separator = "") { byte -> "%02x".format(byte) }

    companion object {
        private const val PREFS_NAME = "background_protection_v1"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_TREE_URI = "protected_tree_uri"
        private const val KEY_LAST_CHECK_AT = "last_check_at"
        private const val KEY_LAST_SCANNED_COUNT = "last_scanned_count"
        private const val KEY_LAST_ALERT_COUNT = "last_alert_count"
        private const val KEY_PERMISSION_LOST = "folder_permission_lost"
        private const val KEY_LEDGER = "document_ledger"
        private const val MAX_LEDGER_ENTRIES = 2000
    }
}
