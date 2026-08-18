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
import com.aman.security.banking.BankingRiskAssessment
import com.aman.security.security.AttackDetectionCenter
import com.aman.security.security.AttackDetectionLevel
import com.aman.security.security.DataExfiltrationFinding
import com.aman.security.runtime.HardeningReport
import com.aman.security.security.IntrusionMonitorSummary
import com.aman.security.R
import com.aman.security.web.LocalWebShieldController

object ProtectionNotifier {
    private const val ALERT_CHANNEL_ID = "aman_protection_alerts"
    private const val STATUS_CHANNEL_ID = "aman_protection_status"
    const val STATUS_NOTIFICATION_ID = 27001
    const val WEB_SHIELD_NOTIFICATION_ID = 27002
    private const val WEB_THREAT_ALERT_ID = 27100
    private const val INTRUSION_ALERT_ID = 27200
    private const val BANKING_ALERT_ID = 27300
    private const val DATA_EXFIL_ALERT_ID = 27400
    private const val BACKGROUND_ACTIVITY_ALERT_ID = 27500
    private const val SPYWARE_ALERT_ID = 27600
    private const val SIDELOAD_SENSITIVE_ALERT_ID = 27650
    private const val LEGACY_DOWNLOAD_REVIEW_ALERT_ID = 27700
    private const val DOWNLOAD_REVIEW_ALERT_ID = 28000
    private const val RUNTIME_OVERLAY_ALERT_ID = 27800
    private const val RUNTIME_MEDIA_ALERT_ID = 27810
    private const val RUNTIME_CLIPBOARD_ALERT_ID = 27820
    private const val RUNTIME_HARDENING_ALERT_ID = 27830
    private const val RUNTIME_INTEGRITY_ALERT_ID = 27840
    private const val RUNTIME_HIDDEN_APP_ALERT_ID = 27850
    private const val RUNTIME_DRAIN_ALERT_ID = 27860

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
        val scan = ScanSessionStore(context).snapshot()
        if (scan.isActive) return buildScanStatusNotification(context, scan)
        val prefs = ProtectionPreferences(context)
        val downloadsReady = prefs.downloadsProtectionEnabled && ProtectionAccess.hasDownloadsReadAccess(context)
        val appMonitorReady = prefs.appInstallMonitorEnabled
        val attack = AttackDetectionCenter(context).snapshot()
        val title = context.getString(
            when (attack.level) {
                AttackDetectionLevel.CRITICAL -> R.string.protection_status_attack_critical_title
                AttackDetectionLevel.WATCH -> R.string.protection_status_attack_watch_title
                else -> if (downloadsReady && appMonitorReady) R.string.protection_status_notification_protected
                else R.string.protection_status_notification_attention
            }
        )
        val body = when (attack.level) {
            AttackDetectionLevel.CRITICAL -> context.getString(R.string.protection_status_attack_critical_body)
            AttackDetectionLevel.WATCH -> context.getString(R.string.protection_status_attack_watch_body)
            else -> when {
                !appMonitorReady -> context.getString(R.string.protection_status_notification_apps_off)
                prefs.downloadsProtectionEnabled && !downloadsReady -> context.getString(R.string.protection_status_notification_downloads_access)
                !prefs.downloadsProtectionEnabled -> context.getString(R.string.protection_status_notification_downloads_off)
                else -> context.getString(
                    R.string.protection_status_notification_body_layers,
                    context.getString(if (LocalWebShieldController.isHealthy(context)) R.string.protection_layer_active else R.string.protection_layer_off),
                    context.getString(if (prefs.intrusionMonitorEnabled) R.string.protection_layer_active else R.string.protection_layer_off)
                )
            }
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

    fun buildWebShieldStatusNotification(context: Context): Notification {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val openPendingIntent = PendingIntent.getActivity(
            context,
            WEB_SHIELD_NOTIFICATION_ID,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(context, STATUS_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(context.getString(R.string.local_web_shield_notification_title))
            .setContentText(context.getString(R.string.local_web_shield_notification_body))
            .setStyle(NotificationCompat.BigTextStyle().bigText(context.getString(R.string.local_web_shield_notification_body)))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setContentIntent(openPendingIntent)
            .build()
    }

    fun notifyWebThreatBlocked(context: Context, host: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, WEB_THREAT_ALERT_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.local_web_shield_blocked_notification_body, host)
        postNotificationSafely(
            context,
            WEB_THREAT_ALERT_ID + host.hashCode().and(0x3ff),
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.local_web_shield_blocked_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyIntrusionChange(context: Context, summary: IntrusionMonitorSummary) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, INTRUSION_ALERT_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(
            R.string.intrusion_change_notification_body,
            summary.totalChanges,
            summary.highChanges
        )
        postNotificationSafely(
            context, INTRUSION_ALERT_ID,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.intrusion_change_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyOverlayAttack(context: Context, appName: String, packageName: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, RUNTIME_OVERLAY_ALERT_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.runtime_overlay_notification_body, appName)
        postNotificationSafely(
            context, RUNTIME_OVERLAY_ALERT_ID,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.runtime_overlay_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyMediaAccess(context: Context, appName: String, packageName: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, RUNTIME_MEDIA_ALERT_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.runtime_media_notification_body, appName)
        postNotificationSafely(
            context, RUNTIME_MEDIA_ALERT_ID,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.runtime_media_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyClipboardGuard(context: Context, contentSummary: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, RUNTIME_CLIPBOARD_ALERT_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.runtime_clipboard_notification_body)
        postNotificationSafely(
            context, RUNTIME_CLIPBOARD_ALERT_ID,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.runtime_clipboard_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyPackageModified(context: Context, packageName: String) {
        ensureChannels(context)
        val label = runCatching {
            val info = context.packageManager.getPackageInfo(packageName, 0)
            info.applicationInfo?.loadLabel(context.packageManager)?.toString().orEmpty()
        }.getOrDefault(packageName)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, RUNTIME_INTEGRITY_ALERT_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.runtime_integrity_notification_body, label)
        postNotificationSafely(
            context, RUNTIME_INTEGRITY_ALERT_ID,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.runtime_integrity_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyHardeningWeakness(context: Context, report: HardeningReport) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, RUNTIME_HARDENING_ALERT_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.runtime_hardening_notification_body, report.score)
        postNotificationSafely(
            context, RUNTIME_HARDENING_ALERT_ID,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.runtime_hardening_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyBankingRisk(context: Context, assessment: BankingRiskAssessment, blocked: Boolean) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, BANKING_ALERT_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val title = context.getString(if (blocked) R.string.banking_block_notification_title else R.string.banking_review_notification_title)
        val body = context.getString(
            if (blocked) R.string.banking_block_notification_body else R.string.banking_review_notification_body,
            assessment.riskyApps.size
        )
        postNotificationSafely(
            context, BANKING_ALERT_ID,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyHighRiskNetworkContact(context: Context, appName: String, host: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, DATA_EXFIL_ALERT_ID + 500, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.high_risk_network_contact_notification_body, appName, host)
        postNotificationSafely(
            context,
            DATA_EXFIL_ALERT_ID + host.hashCode().and(0x1ff),
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.high_risk_network_contact_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyDataExfiltration(context: Context, finding: DataExfiltrationFinding) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, DATA_EXFIL_ALERT_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(
            R.string.data_exfil_notification_body,
            finding.appName,
            android.text.format.Formatter.formatFileSize(context, finding.backgroundTxBytes)
        )
        postNotificationSafely(
            context,
            DATA_EXFIL_ALERT_ID + finding.packageName.hashCode().and(0x3ff),
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.data_exfil_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyBackgroundActivityReview(context: Context, highImpactApps: Int, topAppName: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            BACKGROUND_ACTIVITY_ALERT_ID,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.background_activity_notification_body, highImpactApps)
        val contentText = if (topAppName.isBlank()) body else "$body $topAppName"
        postNotificationSafely(
            context,
            BACKGROUND_ACTIVITY_ALERT_ID,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.background_activity_notification_title))
                .setContentText(contentText)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun updateProtectionStatus(context: Context) {
        if (!ProtectionPreferences(context).enabled && !ScanSessionStore(context).snapshot().isActive) return
        postNotificationSafely(
            context = context,
            notificationId = STATUS_NOTIFICATION_ID,
            notification = buildProtectionStatusNotification(context)
        )
    }


    fun refreshForegroundStatus(context: Context) {
        postNotificationSafely(
            context = context,
            notificationId = STATUS_NOTIFICATION_ID,
            notification = buildProtectionStatusNotification(context)
        )
    }

    private fun buildScanStatusNotification(context: Context, scan: ScanSessionSnapshot): Notification {
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_SCAN)
        }
        val openPendingIntent = PendingIntent.getActivity(
            context, STATUS_NOTIFICATION_ID + 20, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val cancelIntent = Intent(context, ProtectionService::class.java).apply {
            action = ProtectionService.ACTION_CANCEL_SCAN
            putExtra(ProtectionService.EXTRA_SCAN_SESSION_ID, scan.sessionId)
        }
        val cancelPendingIntent = PendingIntent.getService(
            context, STATUS_NOTIFICATION_ID + 21, cancelIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val mode = context.getString(when (scan.mode) {
            PersistentScanMode.QUICK -> R.string.quick_scan_action
            PersistentScanMode.SMART -> R.string.smart_scan_action
            PersistentScanMode.FULL -> R.string.full_scan_action
        })
        val body = context.getString(R.string.persistent_scan_notification_body, scan.progress, mode)
        return NotificationCompat.Builder(context, STATUS_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(context.getString(R.string.persistent_scan_notification_title))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setProgress(100, scan.progress.coerceIn(0, 100), false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openPendingIntent)
            .addAction(0, context.getString(R.string.protection_status_open_action), openPendingIntent)
            .addAction(0, context.getString(R.string.stop_scan), cancelPendingIntent)
            .build()
    }

    fun notifyScanFinished(context: Context, scan: ScanSessionSnapshot) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_SCAN)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, STATUS_NOTIFICATION_ID + 22, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val title = when (scan.state) {
            PersistentScanState.COMPLETED -> context.getString(
                if (scan.totalAlerts > 0) R.string.persistent_scan_finished_attention_title else R.string.persistent_scan_finished_safe_title
            )
            PersistentScanState.CANCELLED -> context.getString(R.string.scan_cancelled_title)
            else -> context.getString(R.string.smart_scan_failed_title)
        }
        val body = when (scan.state) {
            PersistentScanState.COMPLETED -> context.getString(
                R.string.persistent_scan_finished_body, scan.scannedApps, scan.scannedFiles, scan.totalAlerts
            )
            PersistentScanState.CANCELLED -> context.getString(R.string.scan_cancelled_detail)
            else -> context.getString(R.string.persistent_scan_failed_body, scan.error.ifBlank { context.getString(R.string.operation_failed_try_again) })
        }
        postNotificationSafely(
            context, STATUS_NOTIFICATION_ID + 23,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(if (scan.totalAlerts > 0) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        if (ProtectionPreferences(context).enabled) updateProtectionStatus(context)
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
        updateProtectionStatus(context)
    }

    fun cancelDownloadedPackageReviewNotifications(context: Context) {
        val notificationManager = NotificationManagerCompat.from(context)
        // Previous scans used one id per package hash. Clear both the legacy and current
        // ranges, while preserving fixed ids used by other security notification types.
        val reservedIds = setOf(
            RUNTIME_OVERLAY_ALERT_ID,
            RUNTIME_MEDIA_ALERT_ID,
            RUNTIME_CLIPBOARD_ALERT_ID,
            RUNTIME_HARDENING_ALERT_ID,
            RUNTIME_INTEGRITY_ALERT_ID,
            RUNTIME_HIDDEN_APP_ALERT_ID,
            RUNTIME_DRAIN_ALERT_ID
        )
        listOf(LEGACY_DOWNLOAD_REVIEW_ALERT_ID, DOWNLOAD_REVIEW_ALERT_ID).forEach { baseId ->
            for (offset in 0..0x1ff) {
                val notificationId = baseId + offset
                if (notificationId !in reservedIds) notificationManager.cancel(notificationId)
            }
        }
    }

    fun notifyDownloadedPackageReview(context: Context, fileName: String, path: String, sha256: String) {
        // This is a review signal for a newly downloaded package, not a confirmed threat.
        // Never emit it while a durable FULL scan is active, even if an older worker
        // started before the scan and reaches this method later.
        val scan = ScanSessionStore(context).snapshot()
        if (scan.isActive && scan.mode == PersistentScanMode.FULL) return

        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val notificationId = DOWNLOAD_REVIEW_ALERT_ID + sha256.hashCode().and(0x1ff)
        val pendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(
            R.string.download_untrusted_source_notification_body,
            fileName
        )
        postNotificationSafely(
            context,
            notificationId,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.download_untrusted_source_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText("$body\n$path"))
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
    }

    fun notifySideloadedSensitiveApp(context: Context, appName: String, packageName: String, signalCount: Int) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val notificationId = SIDELOAD_SENSITIVE_ALERT_ID + packageName.hashCode().and(0x1ff)
        val pendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(
            R.string.sideload_sensitive_notification_body,
            appName,
            signalCount
        )
        postNotificationSafely(
            context,
            notificationId,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.sideload_sensitive_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifySpywareHighRisk(context: Context, appName: String, packageName: String, signalCount: Int) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            SPYWARE_ALERT_ID + packageName.hashCode().and(0x1ff),
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(
            R.string.spyware_high_notification_body,
            appName,
            signalCount
        )
        postNotificationSafely(
            context,
            SPYWARE_ALERT_ID + packageName.hashCode().and(0x1ff),
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.spyware_high_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
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

    fun notifyHiddenApp(context: Context, label: String, packageName: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, RUNTIME_HIDDEN_APP_ALERT_ID + packageName.hashCode().and(0x3ff), openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.runtime_hidden_app_notification_body, label)
        postNotificationSafely(
            context, RUNTIME_HIDDEN_APP_ALERT_ID + packageName.hashCode().and(0x3ff),
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.runtime_hidden_app_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyBatteryDrain(context: Context, label: String, packageName: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, RUNTIME_DRAIN_ALERT_ID + packageName.hashCode().and(0x3ff), openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.runtime_drain_notification_body, label)
        postNotificationSafely(
            context, RUNTIME_DRAIN_ALERT_ID + packageName.hashCode().and(0x3ff),
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.runtime_drain_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
                updateProtectionStatus(context)
    }

    fun notifyNetworkBeacon(context: Context, label: String, packageName: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, RUNTIME_HIDDEN_APP_ALERT_ID + 1000 + packageName.hashCode().and(0x3ff), openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.runtime_beacon_notification_body, label)
        postNotificationSafely(
            context, RUNTIME_HIDDEN_APP_ALERT_ID + 1000 + packageName.hashCode().and(0x3ff),
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.runtime_beacon_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

    fun notifyLinkRisk(context: Context, summary: String) {
        ensureChannels(context)
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_PAGE, MainActivity.OPEN_PAGE_PROTECTION)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, RUNTIME_DRAIN_ALERT_ID + 1000, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(R.string.runtime_link_risk_notification_body, summary)
        postNotificationSafely(
            context, RUNTIME_DRAIN_ALERT_ID + 1000,
            NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.runtime_link_risk_notification_title))
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()
        )
        updateProtectionStatus(context)
    }

}
