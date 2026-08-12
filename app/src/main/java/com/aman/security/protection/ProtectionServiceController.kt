package com.aman.security.protection

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

object ProtectionServiceController {
    private const val HEALTH_WINDOW_MS = 22 * 60 * 1000L

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
            // Do not force-stop the service if a durable scan is still active.
            if (!ScanSessionStore(app).snapshot().isActive) {
                app.stopService(Intent(app, ProtectionService::class.java))
            }
        }
    }

    fun refresh(context: Context) {
        val app = context.applicationContext
        if (!isHealthy(app) && !ScanSessionStore(app).snapshot().isActive) return
        runCatching {
            app.startService(Intent(app, ProtectionService::class.java).setAction(ProtectionService.ACTION_REFRESH))
        }
    }

    /** Starts one durable scan from a user-visible Activity. Returns the session snapshot. */
    fun startScan(context: Context, mode: PersistentScanMode): ScanSessionSnapshot {
        val app = context.applicationContext
        val store = ScanSessionStore(app)
        val existing = store.snapshot()
        if (existing.isActive) return existing
        val session = store.begin(mode)
        val intent = Intent(app, ProtectionService::class.java)
            .setAction(ProtectionService.ACTION_SCAN)
            .putExtra(ProtectionService.EXTRA_SCAN_SESSION_ID, session.sessionId)
            .putExtra(ProtectionService.EXTRA_SCAN_MODE, session.mode.name)
        runCatching { ContextCompat.startForegroundService(app, intent) }
            .onFailure { store.fail(session.sessionId, it.message ?: it.javaClass.simpleName) }
        return store.snapshot()
    }

    fun cancelScan(context: Context) {
        val app = context.applicationContext
        val store = ScanSessionStore(app)
        val session = store.snapshot()
        if (!session.isActive) return
        store.requestCancel(session.sessionId)
        runCatching {
            app.startService(
                Intent(app, ProtectionService::class.java)
                    .setAction(ProtectionService.ACTION_CANCEL_SCAN)
                    .putExtra(ProtectionService.EXTRA_SCAN_SESSION_ID, session.sessionId)
            )
        }
    }

    /** Boot/package-replace recovery for a scan that was interrupted while active. */
    fun recoverPendingScan(context: Context) {
        val app = context.applicationContext
        val session = ScanSessionStore(app).snapshot()
        if (!session.isActive) return
        val intent = Intent(app, ProtectionService::class.java)
            .setAction(ProtectionService.ACTION_SCAN)
            .putExtra(ProtectionService.EXTRA_SCAN_SESSION_ID, session.sessionId)
            .putExtra(ProtectionService.EXTRA_SCAN_MODE, session.mode.name)
        runCatching { ContextCompat.startForegroundService(app, intent) }
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
