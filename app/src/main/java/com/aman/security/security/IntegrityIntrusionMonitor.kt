package com.aman.security.security

import android.content.Context
import org.json.JSONObject

enum class IntegrityChangeKind {
    ROOT_SIGNAL_ADDED,
    ADB_ENABLED,
    DEVELOPER_OPTIONS_ENABLED,
    SCREEN_LOCK_DISABLED
}

data class IntegrityChange(
    val kind: IntegrityChangeKind,
    val severity: IntrusionChangeSeverity
)

data class IntegrityState(
    val rootSignals: Int,
    val adbEnabled: Boolean,
    val developerOptionsEnabled: Boolean,
    val screenLockSecure: Boolean
)

data class IntegrityMonitorResult(
    val baselineCreated: Boolean,
    val changes: List<IntegrityChange>
)

/**
 * Tracks changes in high-value local device security posture. These are indicators only:
 * a setting change is never called a remote compromise by itself.
 */
class IntegrityIntrusionMonitor(private val context: Context) {
    fun check(): IntegrityMonitorResult {
        val audit = DeviceSecurityAuditor(context).audit()
        val current = IntegrityState(
            rootSignals = audit.rootSignals,
            adbEnabled = audit.adbEnabled,
            developerOptionsEnabled = audit.developerOptionsEnabled,
            screenLockSecure = audit.screenLockSecure
        )
        val store = IntegrityBaselineStore(context)
        val previous = store.read()
        store.write(current)
        if (previous == null) return IntegrityMonitorResult(true, emptyList())

        val changes = buildList {
            if (current.rootSignals > previous.rootSignals) {
                add(IntegrityChange(IntegrityChangeKind.ROOT_SIGNAL_ADDED, IntrusionChangeSeverity.HIGH))
            }
            if (current.adbEnabled && !previous.adbEnabled) {
                add(IntegrityChange(IntegrityChangeKind.ADB_ENABLED, IntrusionChangeSeverity.REVIEW))
            }
            if (current.developerOptionsEnabled && !previous.developerOptionsEnabled) {
                add(IntegrityChange(IntegrityChangeKind.DEVELOPER_OPTIONS_ENABLED, IntrusionChangeSeverity.REVIEW))
            }
            if (!current.screenLockSecure && previous.screenLockSecure) {
                add(IntegrityChange(IntegrityChangeKind.SCREEN_LOCK_DISABLED, IntrusionChangeSeverity.REVIEW))
            }
        }
        return IntegrityMonitorResult(false, changes)
    }
}

class IntegrityBaselineStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun read(): IntegrityState? {
        val raw = prefs.getString(KEY_STATE, null) ?: return null
        return runCatching {
            val json = JSONObject(raw)
            IntegrityState(
                rootSignals = json.optInt("rootSignals", 0),
                adbEnabled = json.optBoolean("adbEnabled", false),
                developerOptionsEnabled = json.optBoolean("developerOptionsEnabled", false),
                screenLockSecure = json.optBoolean("screenLockSecure", true)
            )
        }.getOrNull()
    }

    fun write(state: IntegrityState) {
        val json = JSONObject()
            .put("rootSignals", state.rootSignals)
            .put("adbEnabled", state.adbEnabled)
            .put("developerOptionsEnabled", state.developerOptionsEnabled)
            .put("screenLockSecure", state.screenLockSecure)
            .put("updatedAt", System.currentTimeMillis())
        prefs.edit().putString(KEY_STATE, json.toString()).apply()
    }

    companion object {
        private const val PREFS_NAME = "intrusion_integrity_baseline_v1"
        private const val KEY_STATE = "state"
    }
}
