package com.aman.security.protection

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.aman.security.MainActivity
import com.aman.security.R

object ProtectionNotifier {
    private const val ALERT_CHANNEL_ID = "aman_protection_alerts"
    private const val STATUS_CHANNEL_ID = "aman_protection_status"
    const val STATUS_NOTIFICATION_ID = 27001

    fun ensureChannel(context: Context) = ensureChannels(context)

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java)
        val alerts = NotificationChannel(
            ALERT_CHANNEL_ID,
            context.getString(R.string.protection_channel_name),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = context.getString(R.string.protection_channel_description)
        }
        val status = NotificationChannel(
            STATUS_CHANNEL_ID,
            context.getString(R.string.protection_status_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = context.getString(R.string.protection_status_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(alerts)
        manager.createNotificationChannel(status)
    }

    fun buildProtectionStatusNotification(context: Context): Notification {
        ensureChannels(context)
        val prefs = ProtectionPreferences(context)
        val downloadsReady = prefs.downloadsProtectionEnabled && ProtectionAccess.hasDownloadsReadAccess(context)
        val appMonitorReady = prefs.appInstallMonitorEnabled
        val title = context.getString(
            if (downloadsReady && appMonitorReady) R.string.protection_status_notification_protected
            else R.string.protection_status_notification_attention
        )
        val body = when {
            !appMonitorReady -> context.getString(R.string.protection_status_notification_apps_off)
            prefs.downloadsProtectionEnabled && !downloadsReady -> context.getString(R.string.protection_status_notification_downloads_access)
            !prefs.downloadsProtectionEnabled -> context.getString(R.string.protection_status_notification_downloads_off)
            else -> context.getString(R.string.protection_status_notification_body)
        }
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val openPendingIntent = PendingIntent.getActivity(
            context,
            STATUS_NOTIFICATION_ID,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val scanIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_SCAN)
            putExtra(MainActivity.EXTRA_START_SMART_SCAN, true)
        }
        val scanPendingIntent = PendingIntent.getActivity(
            context,
            STATUS_NOTIFICATION_ID + 1,
            scanIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, STATUS_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setContentIntent(openPendingIntent)
            .addAction(0, context.getString(R.string.protection_status_open_action), openPendingIntent)
            .addAction(0, context.getString(R.string.protection_status_scan_action), scanPendingIntent)
            .build()
    }

    fun updateProtectionStatus(context: Context) {
        if (!ProtectionPreferences(context).enabled) return
        postNotificationSafely(
            context = context,
            notificationId = STATUS_NOTIFICATION_ID,
            notification = buildProtectionStatusNotification(context)
        )
    }

    fun notifyEvent(context: Context, event: ProtectionEvent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            event.id.hashCode(),
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val title = when (event.severity) {
            ProtectionSeverity.KNOWN_THREAT -> context.getString(R.string.protection_notification_known_title)
            ProtectionSeverity.HIGH_RISK -> context.getString(R.string.protection_notification_high_title)
        }
        val body = when (event.type) {
            ProtectionEventType.FILE -> context.getString(R.string.protection_notification_file_body, event.displayName)
            ProtectionEventType.APP -> context.getString(R.string.protection_notification_app_body, event.displayName)
        }

        val notification = NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        postNotificationSafely(
            context = context,
            notificationId = event.id.hashCode(),
            notification = notification
        )
    }

    private fun postNotificationSafely(
        context: Context,
        notificationId: Int,
        notification: Notification
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        try {
            NotificationManagerCompat.from(context).notify(notificationId, notification)
        } catch (_: SecurityException) {
            // Notification permission can be revoked between the explicit check and notify().
            // Protection must continue running; the UI reports notification permission state.
        }
    }
}
