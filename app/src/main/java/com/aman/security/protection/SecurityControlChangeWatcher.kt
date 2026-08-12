package com.aman.security.protection

import android.content.Context
import android.database.ContentObserver
import android.os.Handler
import android.os.Looper
import android.provider.Settings

/**
 * Tiny event-driven trigger for accessibility-control changes. It does not read UI
 * content; it only asks WorkManager to re-evaluate the local privilege baseline.
 */
class SecurityControlChangeWatcher(
    private val context: Context,
    private val onChanged: () -> Unit
) {
    private val handler = Handler(Looper.getMainLooper())
    private var started = false
    private val dispatch = Runnable { onChanged() }
    private val observer = object : ContentObserver(handler) {
        override fun onChange(selfChange: Boolean) {
            handler.removeCallbacks(dispatch)
            handler.postDelayed(dispatch, DEBOUNCE_MS)
        }
    }

    fun start() {
        if (started) return
        started = runCatching {
            context.contentResolver.registerContentObserver(
                Settings.Secure.getUriFor(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES),
                false,
                observer
            )
            true
        }.getOrDefault(false)
    }

    fun stop() {
        if (!started) return
        runCatching { context.contentResolver.unregisterContentObserver(observer) }
        handler.removeCallbacks(dispatch)
        started = false
    }

    companion object {
        private const val DEBOUNCE_MS = 2_000L
    }
}
