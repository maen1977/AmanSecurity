package com.aman.security.protection

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.content.ContextCompat

object ProtectionServiceController {
    private const val HEALTH_WINDOW_MS = 3 * 60 * 1000L

    fun start(context: Context) {
        val app = context.applicationContext
        val intent = Intent(app, ProtectionService::class.java).setAction(ProtectionService.ACTION_START)
        ContextCompat.startForegroundService(app, intent)
    }

    fun stop(context: Context) {
        val app = context.applicationContext
        runCatching {
            app.startService(Intent(app, ProtectionService::class.java).setAction(ProtectionService.ACTION_STOP))
        }.onFailure {
            app.stopService(Intent(app, ProtectionService::class.java))
        }
    }

    fun refresh(context: Context) {
        val app = context.applicationContext
        // Avoid background-starting a new FGS just to refresh. If the service is healthy,
        // starting an already-running service is safe; otherwise the UI/boot path can restart it.
        if (!isHealthy(app)) return
        runCatching {
            app.startService(Intent(app, ProtectionService::class.java).setAction(ProtectionService.ACTION_REFRESH))
        }
    }

    fun isHealthy(context: Context, now: Long = System.currentTimeMillis()): Boolean {
        val prefs = ProtectionPreferences(context)
        if (!prefs.enabled) return false
        val heartbeat = prefs.serviceHeartbeatAt
        return heartbeat > 0L && now - heartbeat in 0..HEALTH_WINDOW_MS
    }

    fun needsRecovery(context: Context, now: Long = System.currentTimeMillis()): Boolean {
        val prefs = ProtectionPreferences(context)
        return prefs.enabled && !isHealthy(context, now)
    }
}
