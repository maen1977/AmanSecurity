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

    var lastAppRescanAt: Long
        get() = prefs.getLong(KEY_LAST_APP_RESCAN_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_APP_RESCAN_AT, value).apply()

    var lastAppRescanCount: Int
        get() = prefs.getInt(KEY_LAST_APP_RESCAN_COUNT, 0)
        set(value) = prefs.edit().putInt(KEY_LAST_APP_RESCAN_COUNT, value).apply()

    var lastAppAlertCount: Int
        get() = prefs.getInt(KEY_LAST_APP_ALERT_COUNT, 0)
        set(value) = prefs.edit().putInt(KEY_LAST_APP_ALERT_COUNT, value).apply()

    var appInstallMonitorEnabled: Boolean
        get() = prefs.getBoolean(KEY_APP_INSTALL_MONITOR, true)
        set(value) = prefs.edit().putBoolean(KEY_APP_INSTALL_MONITOR, value).apply()

    var downloadsProtectionEnabled: Boolean
        get() = prefs.getBoolean(KEY_DOWNLOADS_PROTECTION, true)
        set(value) = prefs.edit().putBoolean(KEY_DOWNLOADS_PROTECTION, value).apply()

    var periodicAppRescanEnabled: Boolean
        get() = prefs.getBoolean(KEY_PERIODIC_APP_RESCAN, true)
        set(value) = prefs.edit().putBoolean(KEY_PERIODIC_APP_RESCAN, value).apply()

    var serviceStartedAt: Long
        get() = prefs.getLong(KEY_SERVICE_STARTED_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_SERVICE_STARTED_AT, value).apply()

    var serviceHeartbeatAt: Long
        get() = prefs.getLong(KEY_SERVICE_HEARTBEAT_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_SERVICE_HEARTBEAT_AT, value).apply()

    var lastActivityAt: Long
        get() = prefs.getLong(KEY_LAST_ACTIVITY_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_ACTIVITY_AT, value).apply()

    var lastActivityLabel: String?
        get() = prefs.getString(KEY_LAST_ACTIVITY_LABEL, null)
        set(value) = prefs.edit().putString(KEY_LAST_ACTIVITY_LABEL, value).apply()

    var totalAppsChecked: Long
        get() = prefs.getLong(KEY_TOTAL_APPS_CHECKED, 0L)
        set(value) = prefs.edit().putLong(KEY_TOTAL_APPS_CHECKED, value.coerceAtLeast(0L)).apply()

    var totalFilesChecked: Long
        get() = prefs.getLong(KEY_TOTAL_FILES_CHECKED, 0L)
        set(value) = prefs.edit().putLong(KEY_TOTAL_FILES_CHECKED, value.coerceAtLeast(0L)).apply()

    var totalThreatsDetected: Long
        get() = prefs.getLong(KEY_TOTAL_THREATS_DETECTED, 0L)
        set(value) = prefs.edit().putLong(KEY_TOTAL_THREATS_DETECTED, value.coerceAtLeast(0L)).apply()

    var lastDownloadsScanAt: Long
        get() = prefs.getLong(KEY_LAST_DOWNLOADS_SCAN_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_DOWNLOADS_SCAN_AT, value).apply()

    var lastDownloadsScannedCount: Int
        get() = prefs.getInt(KEY_LAST_DOWNLOADS_SCANNED_COUNT, 0)
        set(value) = prefs.edit().putInt(KEY_LAST_DOWNLOADS_SCANNED_COUNT, value.coerceAtLeast(0)).apply()

    var lastDownloadsAlertCount: Int
        get() = prefs.getInt(KEY_LAST_DOWNLOADS_ALERT_COUNT, 0)
        set(value) = prefs.edit().putInt(KEY_LAST_DOWNLOADS_ALERT_COUNT, value.coerceAtLeast(0)).apply()

    var lastCachedReputationSweepAt: Long
        get() = prefs.getLong(KEY_LAST_CACHED_SWEEP_AT, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_CACHED_SWEEP_AT, value).apply()

    var lastCachedReputationSweepCount: Int
        get() = prefs.getInt(KEY_LAST_CACHED_SWEEP_COUNT, 0)
        set(value) = prefs.edit().putInt(KEY_LAST_CACHED_SWEEP_COUNT, value.coerceAtLeast(0)).apply()

    @Synchronized
    fun downloadLedger(): MutableMap<String, String> {
        val raw = prefs.getString(KEY_DOWNLOAD_LEDGER, null) ?: return linkedMapOf()
        return runCatching {
            val json = JSONObject(raw)
            val result = linkedMapOf<String, String>()
            json.keys().forEach { key -> result[key] = json.optString(key) }
            result
        }.getOrDefault(linkedMapOf())
    }

    @Synchronized
    fun saveDownloadLedger(values: Map<String, String>) {
        val bounded = values.entries.toList().takeLast(MAX_DOWNLOAD_LEDGER_ENTRIES)
        val json = JSONObject()
        bounded.forEach { (key, value) -> json.put(key, value) }
        prefs.edit().putString(KEY_DOWNLOAD_LEDGER, json.toString()).apply()
    }

    fun clearDownloadLedger() = prefs.edit().remove(KEY_DOWNLOAD_LEDGER).apply()

    fun markActivity(label: String) {
        val now = System.currentTimeMillis()
        prefs.edit()
            .putLong(KEY_LAST_ACTIVITY_AT, now)
            .putString(KEY_LAST_ACTIVITY_LABEL, label.take(240))
            .apply()
    }

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

    @Synchronized
    fun appLedger(): MutableMap<String, String> {
        val raw = prefs.getString(KEY_APP_LEDGER, null) ?: return linkedMapOf()
        return runCatching {
            val json = JSONObject(raw)
            val result = linkedMapOf<String, String>()
            json.keys().forEach { key -> result[key] = json.optString(key) }
            result
        }.getOrDefault(linkedMapOf())
    }

    @Synchronized
    fun replaceAppFingerprint(packageName: String, fingerprint: String): String? {
        val values = appLedger()
        val previous = values.put(packageName, fingerprint)
        saveAppLedger(values)
        return previous
    }

    @Synchronized
    fun pruneAppLedger(activePackages: Set<String>) {
        val values = appLedger().filterKeys { it in activePackages }
        saveAppLedger(values)
    }

    @Synchronized
    fun saveAppLedger(values: Map<String, String>) {
        val bounded = values.entries.toList().takeLast(MAX_APP_LEDGER_ENTRIES)
        val json = JSONObject()
        bounded.forEach { (key, value) -> json.put(key, value) }
        prefs.edit().putString(KEY_APP_LEDGER, json.toString()).apply()
    }

    fun clearAppLedger() = prefs.edit().remove(KEY_APP_LEDGER).apply()

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
        private const val KEY_APP_LEDGER = "app_detection_ledger"
        private const val KEY_LAST_APP_RESCAN_AT = "last_app_rescan_at"
        private const val KEY_LAST_APP_RESCAN_COUNT = "last_app_rescan_count"
        private const val KEY_LAST_APP_ALERT_COUNT = "last_app_alert_count"

        private const val KEY_APP_INSTALL_MONITOR = "app_install_monitor_enabled"
        private const val KEY_DOWNLOADS_PROTECTION = "downloads_protection_enabled"
        private const val KEY_PERIODIC_APP_RESCAN = "periodic_app_rescan_enabled"
        private const val KEY_SERVICE_STARTED_AT = "service_started_at"
        private const val KEY_SERVICE_HEARTBEAT_AT = "service_heartbeat_at"
        private const val KEY_LAST_ACTIVITY_AT = "last_activity_at"
        private const val KEY_LAST_ACTIVITY_LABEL = "last_activity_label"
        private const val KEY_TOTAL_APPS_CHECKED = "total_apps_checked"
        private const val KEY_TOTAL_FILES_CHECKED = "total_files_checked"
        private const val KEY_TOTAL_THREATS_DETECTED = "total_threats_detected"
        private const val KEY_LAST_DOWNLOADS_SCAN_AT = "last_downloads_scan_at"
        private const val KEY_LAST_DOWNLOADS_SCANNED_COUNT = "last_downloads_scanned_count"
        private const val KEY_LAST_DOWNLOADS_ALERT_COUNT = "last_downloads_alert_count"
        private const val KEY_LAST_CACHED_SWEEP_AT = "last_cached_reputation_sweep_at"
        private const val KEY_LAST_CACHED_SWEEP_COUNT = "last_cached_reputation_sweep_count"
        private const val KEY_DOWNLOAD_LEDGER = "downloads_file_ledger"
        private const val MAX_LEDGER_ENTRIES = 2000
        private const val MAX_APP_LEDGER_ENTRIES = 1500
        private const val MAX_DOWNLOAD_LEDGER_ENTRIES = 4000
    }
}
