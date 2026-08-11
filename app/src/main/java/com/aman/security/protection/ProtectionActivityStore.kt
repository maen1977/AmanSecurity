package com.aman.security.protection

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

enum class ProtectionActivityKind {
    SERVICE,
    APP_SCAN,
    FILE_SCAN,
    DOWNLOAD_SCAN,
    DATABASE_UPDATE,
    WEB_CHECK,
    SECURITY_AUDIT
}

enum class ProtectionActivityState {
    INFO,
    SAFE,
    ATTENTION,
    THREAT
}

data class ProtectionActivityEntry(
    val id: String,
    val kind: ProtectionActivityKind,
    val state: ProtectionActivityState,
    val title: String,
    val detail: String?,
    val createdAt: Long
)

/**
 * Local, bounded protection timeline. This is deliberately separate from the
 * threat-only event store: users need proof that background protection is
 * alive even when no malware is found.
 */
class ProtectionActivityStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    @Synchronized
    fun entries(): List<ProtectionActivityEntry> {
        val raw = prefs.getString(KEY_ENTRIES, null) ?: return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { fromJson(array.optJSONObject(it)) }
                .sortedByDescending { it.createdAt }
        }.getOrDefault(emptyList())
    }

    @Synchronized
    fun add(
        kind: ProtectionActivityKind,
        state: ProtectionActivityState,
        title: String,
        detail: String? = null,
        dedupeKey: String? = null
    ): ProtectionActivityEntry {
        val event = ProtectionActivityEntry(
            id = UUID.randomUUID().toString(),
            kind = kind,
            state = state,
            title = title.take(MAX_TITLE_CHARS),
            detail = detail?.take(MAX_DETAIL_CHARS),
            createdAt = System.currentTimeMillis()
        )
        val previous = entries()
        val filtered = if (dedupeKey.isNullOrBlank()) previous else previous.filterNot {
            "${it.kind}:${it.title}:${it.detail}" == dedupeKey
        }
        write((listOf(event) + filtered).take(MAX_ENTRIES))
        return event
    }

    @Synchronized
    fun clear() = prefs.edit().remove(KEY_ENTRIES).apply()

    private fun write(entries: List<ProtectionActivityEntry>) {
        val array = JSONArray()
        entries.forEach { entry ->
            array.put(
                JSONObject()
                    .put("id", entry.id)
                    .put("kind", entry.kind.name)
                    .put("state", entry.state.name)
                    .put("title", entry.title)
                    .put("detail", entry.detail ?: JSONObject.NULL)
                    .put("createdAt", entry.createdAt)
            )
        }
        prefs.edit().putString(KEY_ENTRIES, array.toString()).apply()
    }

    private fun fromJson(json: JSONObject?): ProtectionActivityEntry? = json?.let {
        runCatching {
            ProtectionActivityEntry(
                id = it.getString("id"),
                kind = ProtectionActivityKind.valueOf(it.getString("kind")),
                state = ProtectionActivityState.valueOf(it.getString("state")),
                title = it.getString("title"),
                detail = it.optString("detail").takeIf { value -> value.isNotBlank() && value != "null" },
                createdAt = it.getLong("createdAt")
            )
        }.getOrNull()
    }

    companion object {
        private const val PREFS_NAME = "protection_timeline_v1"
        private const val KEY_ENTRIES = "entries"
        private const val MAX_ENTRIES = 100
        private const val MAX_TITLE_CHARS = 160
        private const val MAX_DETAIL_CHARS = 800
    }
}
