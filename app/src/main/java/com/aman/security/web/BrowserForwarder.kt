package com.aman.security.web

import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri

object BrowserForwarder {
    /**
     * Hands an already-scanned URL to another browser without pre-querying installed apps.
     *
     * Android 11+ intentionally limits package visibility. Starting an ACTION_VIEW intent does
     * not require package visibility, so asking PackageManager for browsers first can produce a
     * false "no browser" result on some OEM builds. A chooser also prevents Aman (which may hold
     * the browser role) from immediately receiving its own forwarded link again.
     */
    fun openExternal(context: Context, normalizedUrl: String, chooserTitle: String): Boolean {
        val uri = runCatching { Uri.parse(normalizedUrl) }.getOrNull() ?: return false
        if (uri.scheme != "http" && uri.scheme != "https") return false

        val target = Intent(Intent.ACTION_VIEW, uri).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val chooser = Intent.createChooser(target, chooserTitle).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            // Aman can be the system browser-role holder. Exclude Link Guard itself so forwarding
            // a clean link cannot recurse back into the scanner.
            putExtra(
                Intent.EXTRA_EXCLUDE_COMPONENTS,
                arrayOf(ComponentName(context, LinkGuardActivity::class.java))
            )
        }

        return try {
            context.startActivity(chooser)
            true
        } catch (_: ActivityNotFoundException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }
}
