package com.aman.security.protection

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

class ProtectionEventStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    @Synchronized
    fun events(): List<ProtectionEvent> {
        val raw = prefs.getString(KEY_EVENTS, null) ?: return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { index -> fromJson(array.optJSONObject(index)) }
                .sortedByDescending { it.detectedAt }
        }.getOrDefault(emptyList())
    }

    @Synchronized
    fun add(
        type: ProtectionEventType,
        displayName: String,
        detail: String?,
        severity: ProtectionSeverity
    ): ProtectionEvent {
        val event = ProtectionEvent(
            id = UUID.randomUUID().toString(),
            type = type,
            displayName = displayName,
            detail = detail,
            severity = severity,
            detectedAt = System.currentTimeMillis()
        )
        val updated = listOf(event) + events().filterNot {
            it.type == type && it.displayName == displayName && it.detail == detail && it.severity == severity
        }
        write(updated.take(MAX_EVENTS))
        return event
    }

    @Synchronized
    fun clear() = prefs.edit().remove(KEY_EVENTS).apply()

    private fun write(events: List<ProtectionEvent>) {
        val array = JSONArray()
        events.forEach { event ->
            array.put(
                JSONObject()
                    .put("id", event.id)
                    .put("type", event.type.name)
                    .put("displayName", event.displayName)
                    .put("detail", event.detail ?: JSONObject.NULL)
                    .put("severity", event.severity.name)
                    .put("detectedAt", event.detectedAt)
            )
        }
        prefs.edit().putString(KEY_EVENTS, array.toString()).apply()
    }

    private fun fromJson(json: JSONObject?): ProtectionEvent? = json?.let {
        runCatching {
            ProtectionEvent(
                id = it.getString("id"),
                type = ProtectionEventType.valueOf(it.getString("type")),
                displayName = it.getString("displayName"),
                detail = it.optString("detail").takeIf { value -> value.isNotBlank() && value != "null" },
                severity = ProtectionSeverity.valueOf(it.getString("severity")),
                detectedAt = it.getLong("detectedAt")
            )
        }.getOrNull()
    }

    companion object {
        private const val PREFS_NAME = "protection_events_v1"
        private const val KEY_EVENTS = "events"
        private const val MAX_EVENTS = 50
    }
}
