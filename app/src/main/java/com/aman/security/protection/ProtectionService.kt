package com.aman.security.protection

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.ServiceCompat
import com.aman.security.R
import java.io.File

/**
 * User-visible real-time protection coordinator.
 *
 * Android does not allow a third-party antivirus to intercept every file I/O like a
 * desktop kernel driver. This service therefore coordinates the protection surfaces
 * Android does expose: install/update broadcasts, Downloads monitoring (when the user
 * grants the antivirus all-files access), periodic catch-up scans, threat-intelligence
 * refreshes and a persistent protection-status notification.
 */
class ProtectionService : Service() {
    private lateinit var preferences: ProtectionPreferences
    private lateinit var activityStore: ProtectionActivityStore
    private val handler = Handler(Looper.getMainLooper())
    private var downloadsObserver: FileObserver? = null
    private var securityControlWatcher: SecurityControlChangeWatcher? = null

    private val heartbeat = object : Runnable {
        override fun run() {
            if (!preferences.enabled) {
                stopProtectionService()
                return
            }
            preferences.serviceHeartbeatAt = System.currentTimeMillis()
            ProtectionNotifier.updateProtectionStatus(this@ProtectionService)
            ensureDownloadsObserver()
            ensureSecurityControlWatcher()
            handler.postDelayed(this, HEARTBEAT_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        preferences = ProtectionPreferences(this)
        activityStore = ProtectionActivityStore(this)
        ProtectionNotifier.ensureChannels(this)
        securityControlWatcher = SecurityControlChangeWatcher(this) {
            if (preferences.enabled && preferences.intrusionMonitorEnabled) {
                ProtectionScheduler.intrusionCheckNow(applicationContext)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProtectionService()
                return START_NOT_STICKY
            }
        }

        if (!preferences.enabled) {
            stopSelf()
            return START_NOT_STICKY
        }

        val now = System.currentTimeMillis()
        if (preferences.serviceStartedAt <= 0L || now - preferences.serviceHeartbeatAt > STALE_RESTART_MS) {
            preferences.serviceStartedAt = now
            activityStore.add(
                kind = ProtectionActivityKind.SERVICE,
                state = ProtectionActivityState.INFO,
                title = getString(R.string.timeline_realtime_started),
                detail = getString(R.string.timeline_realtime_started_detail),
                dedupeKey = "${ProtectionActivityKind.SERVICE}:${getString(R.string.timeline_realtime_started)}:${getString(R.string.timeline_realtime_started_detail)}"
            )
        }
        preferences.serviceHeartbeatAt = now
        preferences.markActivity(getString(R.string.activity_realtime_active))

        val notification = ProtectionNotifier.buildProtectionStatusNotification(this)
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else 0
        ServiceCompat.startForeground(
            this,
            ProtectionNotifier.STATUS_NOTIFICATION_ID,
            notification,
            type
        )

        ensureDownloadsObserver()
        ensureSecurityControlWatcher()
        handler.removeCallbacks(heartbeat)
        handler.postDelayed(heartbeat, HEARTBEAT_MS)
        return START_STICKY
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        downloadsObserver?.stopWatching()
        downloadsObserver = null
        securityControlWatcher?.stop()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null


    private fun ensureSecurityControlWatcher() {
        if (preferences.enabled && preferences.intrusionMonitorEnabled) {
            securityControlWatcher?.start()
        } else {
            securityControlWatcher?.stop()
        }
    }

    private fun ensureDownloadsObserver() {
        if (!preferences.enabled || !preferences.downloadsProtectionEnabled ||
            !ProtectionAccess.hasDownloadsReadAccess(this)
        ) {
            downloadsObserver?.stopWatching()
            downloadsObserver = null
            return
        }
        if (downloadsObserver != null) return

        @Suppress("DEPRECATION")
        val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!downloads.exists() || !downloads.canRead()) return
        downloadsObserver = object : FileObserver(
            downloads.absolutePath,
            FileObserver.CREATE or FileObserver.MOVED_TO or FileObserver.CLOSE_WRITE
        ) {
            override fun onEvent(event: Int, relativePath: String?) {
                val child = relativePath?.takeIf { it.isNotBlank() } ?: return
                val file = File(downloads, child)
                if (!file.isFile || !file.canRead()) return
                preferences.markActivity(getString(R.string.activity_download_detected, file.name))
                ProtectionScheduler.scanDownloadedFile(applicationContext, file.absolutePath)
            }
        }.also { it.startWatching() }
    }

    private fun stopProtectionService() {
        handler.removeCallbacksAndMessages(null)
        downloadsObserver?.stopWatching()
        downloadsObserver = null
        securityControlWatcher?.stop()
        preferences.serviceHeartbeatAt = 0L
        preferences.serviceStartedAt = 0L
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    companion object {
        const val ACTION_START = "com.aman.security.action.START_PROTECTION"
        const val ACTION_STOP = "com.aman.security.action.STOP_PROTECTION"
        const val ACTION_REFRESH = "com.aman.security.action.REFRESH_PROTECTION"
        private const val HEARTBEAT_MS = 10 * 60_000L
        private const val STALE_RESTART_MS = 25 * 60_000L
    }
}
