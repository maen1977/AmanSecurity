package com.aman.security.scanner

import java.net.URI

/**
 * Industry test pages that are intentionally harmless but should be stopped by
 * a configured anti-phishing link guard. This list is deliberately narrow: it
 * matches the exact AMTSO Android phishing-check path, never the whole AMTSO domain.
 */
object OfficialWebTestIndicators {
    const val AMTSO_ANDROID_PHISHING_URL = "https://www.amtso.org/check-android-phishing-page/"
    const val AMTSO_ANDROID_PHISHING_REFERENCE = "AMTSO_ANDROID_PHISHING_TEST"

    fun match(normalizedUrl: String, host: String): String? {
        if (host != "www.amtso.org" && host != "amtso.org") return null
        val path = runCatching { URI(normalizedUrl).path.orEmpty() }.getOrDefault("")
            .trimEnd('/')
        return if (path == "/check-android-phishing-page") AMTSO_ANDROID_PHISHING_REFERENCE else null
    }
}
