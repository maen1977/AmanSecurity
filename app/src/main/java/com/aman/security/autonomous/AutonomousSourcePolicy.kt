package com.aman.security.autonomous

import java.net.URI
import java.util.Locale

object AutonomousSourcePolicy {
    fun allowed(urlText: String): Boolean {
        val uri = runCatching { URI(urlText) }.getOrNull() ?: return false
        if (uri.scheme?.lowercase(Locale.ROOT) != "https" || uri.userInfo != null || uri.fragment != null) return false
        val host = uri.host?.lowercase(Locale.ROOT) ?: return false
        val path = uri.path ?: return false
        val query = uri.rawQuery
        return when (host) {
            "bazaar.abuse.ch" -> query == null && path == "/browse/tag/Android/"
            "api.destroy.tools" -> query == null && (path == "/v1/feed/primary_active" || path == "/v1/feed/community_active")
            "openphish.com" -> query == null && path == "/feed.txt"
            "feodotracker.abuse.ch" -> query == null && path == "/downloads/ipblocklist_recommended.json"
            "urlhaus.abuse.ch" -> query == null && path == "/downloads/text/"
            "source.android.com" -> (query == null || query == "hl=en") &&
                (path == "/docs/security/bulletin/asb-overview" || path.matches(Regex("^/docs/security/bulletin/20\\d{2}-\\d{2}-01$")))
            else -> false
        }
    }

    fun textPayloadAllowed(bytes: ByteArray): Boolean {
        if (bytes.size >= 4) {
            val b0 = bytes[0].toInt() and 0xff; val b1 = bytes[1].toInt() and 0xff
            val b2 = bytes[2].toInt() and 0xff; val b3 = bytes[3].toInt() and 0xff
            if (b0 == 0x50 && b1 == 0x4b && b2 == 0x03 && b3 == 0x04) return false // ZIP/APK
            if (b0 == 0x7f && b1 == 0x45 && b2 == 0x4c && b3 == 0x46) return false // ELF
            if (b0 == 0x64 && b1 == 0x65 && b2 == 0x78 && b3 == 0x0a) return false // DEX
        }
        if (bytes.size >= 2 && bytes[0] == 'M'.code.toByte() && bytes[1] == 'Z'.code.toByte()) return false // PE
        return true
    }
}
