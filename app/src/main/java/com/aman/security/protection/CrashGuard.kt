package com.aman.security.protection

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.aman.security.MainActivity
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * CrashGuard: catches uncaught exceptions at the process level, writes the
 * full stack trace to a log file, shows a visible user notification, and
 * rethrows so the Android crash loop dialog can still reach the developer.
 *
 * This turned out to be essential after 9.0.0: it lets us learn the exact
 * failure cause from a user's device without any cloud service.
 */
public object CrashGuard {
    private const val LOG_DIR = "crash_logs"
    private const val MAX_LOGS = 20
    private const val NOTIFICATION_ID = 29401
    private const val CHANNEL_ID = "aman_crash_alerts"

    fun install(context: Context) {
        val handler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                val log = buildLog(thread, throwable)
                val dir = File(context.applicationContext.filesDir, LOG_DIR)
                runCatching { dir.mkdirs() }
                trim(dir)
                val file = File(
                    dir,
                    "crash_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date()) + ".log"
                )
                file.writeText(log)
                showNotification(context.applicationContext, file.name)
            }
            handler?.uncaughtException(thread, throwable)
        }
    }

    private fun buildLog(thread: Thread, throwable: Throwable): String {
        val writer = StringWriter()
        PrintWriter(writer).use { throwable.printStackTrace(it) }
        return buildString {
            appendLine("timestamp: " + SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.US).format(Date()))
            appendLine("thread: ${thread.name}")
            appendLine("exception: ${throwable::class.java.name}: ${throwable.message}")
            appendLine(writer.toString())
        }
    }

    private fun trim(dir: File) {
        val files = (dir.listFiles() ?: emptyArray()).filter { it.isFile }.sortedBy { it.lastModified() }.toMutableList()
        while (files.size >= MAX_LOGS && files.isNotEmpty()) {
            files.first().delete()
            files.removeFirst()
        }
    }

    private fun showNotification(context: Context, fileName: String) {
        runCatching {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                val manager = context.getSystemService(NotificationManager::class.java)
                manager?.createNotificationChannel(
                    android.app.NotificationChannel(
                        CHANNEL_ID, "Crash alerts", NotificationManager.IMPORTANCE_HIGH
                    )
                )
            }
            val intent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            val pending = PendingIntent.getActivity(
                context, NOTIFICATION_ID, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_error)
                .setContentTitle("Maen Shield: internal error captured")
                .setContentText("Error log saved: $fileName — please share this file with the developer.")
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pending)
                .build()
            val manager = context.getSystemService(NotificationManager::class.java)
            manager?.notify(NOTIFICATION_ID, notification)
        }
    }
}
