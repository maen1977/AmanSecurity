package com.aman.security.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

enum class IntrusionChangeSeverity {
    REVIEW,
    HIGH
}

data class IntrusionPrivilegeChange(
    val appName: String,
    val packageName: String,
    val addedKinds: Set<PrivilegedAccessKind>,
    val severity: IntrusionChangeSeverity,
    val sideloaded: Boolean
)

data class IntrusionMonitorSummary(
    val baselineCreated: Boolean,
    val scannedPrivilegedApps: Int,
    val changes: List<IntrusionPrivilegeChange>,
    val integrityChanges: List<IntegrityChange> = emptyList()
) {
    val highChanges: Int = changes.count { it.severity == IntrusionChangeSeverity.HIGH } +
        integrityChanges.count { it.severity == IntrusionChangeSeverity.HIGH }
    val reviewChanges: Int = changes.count { it.severity == IntrusionChangeSeverity.REVIEW } +
        integrityChanges.count { it.severity == IntrusionChangeSeverity.REVIEW }
    val totalChanges: Int = changes.size + integrityChanges.size
}

class IntrusionBaselineStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    @Synchronized
    fun read(): Map<String, Set<PrivilegedAccessKind>>? {
        val raw = prefs.getString(KEY_SNAPSHOT, null) ?: return null
        return runCatching {
            val root = JSONObject(raw)
            val packages = root.optJSONArray("packages") ?: JSONArray()
            buildMap {
                for (index in 0 until packages.length()) {
                    val item = packages.optJSONObject(index) ?: continue
                    val packageName = item.optString("packageName")
                    if (packageName.isBlank()) continue
                    val kindsJson = item.optJSONArray("kinds") ?: JSONArray()
                    val kinds = buildSet {
                        for (kindIndex in 0 until kindsJson.length()) {
                            runCatching { PrivilegedAccessKind.valueOf(kindsJson.getString(kindIndex)) }
                                .getOrNull()?.let(::add)
                        }
                    }
                    put(packageName, kinds)
                }
            }
        }.getOrNull()
    }

    @Synchronized
    fun write(snapshot: PrivilegedAccessSnapshot) {
        val packages = JSONArray()
        snapshot.apps.forEach { app ->
            val kinds = JSONArray()
            app.kinds.sortedBy { it.name }.forEach { kinds.put(it.name) }
            packages.put(
                JSONObject()
                    .put("packageName", app.packageName)
                    .put("kinds", kinds)
            )
        }
        val root = JSONObject()
            .put("updatedAt", System.currentTimeMillis())
            .put("packages", packages)
        prefs.edit().putString(KEY_SNAPSHOT, root.toString()).apply()
    }

    companion object {
        private const val PREFS_NAME = "intrusion_baseline_v1"
        private const val KEY_SNAPSHOT = "snapshot"
    }
}

object IntrusionChangePolicy {
    fun assess(app: PrivilegedAccessApp, added: Set<PrivilegedAccessKind>): IntrusionChangeSeverity {
        val controlAdded = added.any {
            it == PrivilegedAccessKind.ACCESSIBILITY || it == PrivilegedAccessKind.DEVICE_ADMIN
        }
        val surveillanceAdded = added.any {
            it == PrivilegedAccessKind.NOTIFICATION_LISTENER || it == PrivilegedAccessKind.OVERLAY
        }
        val powerfulCount = app.kinds.count {
            it == PrivilegedAccessKind.ACCESSIBILITY ||
                it == PrivilegedAccessKind.DEVICE_ADMIN ||
                it == PrivilegedAccessKind.NOTIFICATION_LISTENER
        }
        return if (
            app.sideloaded && controlAdded ||
            (app.sideloaded && powerfulCount >= 2) ||
            (controlAdded && surveillanceAdded && app.kinds.size >= 3)
        ) IntrusionChangeSeverity.HIGH else IntrusionChangeSeverity.REVIEW
    }
}

class IntrusionMonitor(private val context: Context) {
    fun check(): IntrusionMonitorSummary {
        val auditor = PrivilegedAccessAuditor(context)
        val current = auditor.audit()
        val store = IntrusionBaselineStore(context)
        val previous = store.read()
        val integrityResult = IntegrityIntrusionMonitor(context).check()
        if (previous == null) {
            store.write(current)
            return IntrusionMonitorSummary(
                baselineCreated = true,
                scannedPrivilegedApps = current.apps.size,
                changes = emptyList(),
                integrityChanges = integrityResult.changes
            )
        }

        val changes = current.apps.mapNotNull { app ->
            if (app.systemApp) return@mapNotNull null
            val oldKinds = previous[app.packageName].orEmpty()
            val added = app.kinds - oldKinds
            if (added.isEmpty()) return@mapNotNull null
            IntrusionPrivilegeChange(
                appName = app.appName,
                packageName = app.packageName,
                addedKinds = added,
                severity = IntrusionChangePolicy.assess(app, added),
                sideloaded = app.sideloaded
            )
        }.sortedWith(
            compareByDescending<IntrusionPrivilegeChange> { it.severity }
                .thenByDescending { it.addedKinds.size }
        )
        store.write(current)
        return IntrusionMonitorSummary(
            baselineCreated = false,
            scannedPrivilegedApps = current.apps.size,
            changes = changes,
            integrityChanges = integrityResult.changes
        )
    }
}
