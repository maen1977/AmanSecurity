package com.aman.security.web

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.aman.security.protection.ProtectionPreferences

object LocalWebShieldController {
    private const val HEALTH_WINDOW_MS = 25 * 60_000L

    fun prepareIntent(context: Context): Intent? = VpnService.prepare(context)

    fun start(context: Context) {
        val app = context.applicationContext
        val prefs = ProtectionPreferences(app)
        if (!prefs.enabled || !prefs.localWebShieldEnabled || VpnService.prepare(app) != null) return
        ContextCompat.startForegroundService(
            app,
            Intent(app, LocalDnsVpnService::class.java).setAction(LocalDnsVpnService.ACTION_START)
        )
    }

    fun stop(context: Context) {
        val app = context.applicationContext
        runCatching {
            app.startService(Intent(app, LocalDnsVpnService::class.java).setAction(LocalDnsVpnService.ACTION_STOP))
        }.onFailure {
            app.stopService(Intent(app, LocalDnsVpnService::class.java))
        }
    }

    fun refresh(context: Context) {
        val app = context.applicationContext
        if (!isHealthy(app)) return
        runCatching {
            app.startService(
                Intent(app, LocalDnsVpnService::class.java).setAction(LocalDnsVpnService.ACTION_REFRESH)
            )
        }
    }

    fun isPermissionGranted(context: Context): Boolean = VpnService.prepare(context) == null

    fun isHealthy(context: Context, now: Long = System.currentTimeMillis()): Boolean {
        val prefs = ProtectionPreferences(context)
        val heartbeat = prefs.localWebShieldHeartbeatAt
        return prefs.localWebShieldEnabled && isPermissionGranted(context) &&
            heartbeat > 0L && now - heartbeat in 0..HEALTH_WINDOW_MS
    }
}
