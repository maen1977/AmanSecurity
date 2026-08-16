package com.aman.security.runtime

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import com.aman.security.protection.ProtectionPreferences

/**
 * Live camera and microphone usage guard for protected sessions.
 *
 * Modern security suites flag when a non-trusted application accesses the
 * camera or microphone while a sensitive app (banking, payments, OTP) is
 * in the foreground. Implemented with AppOpsManager (permission ops),
 * fully on-device, no network, no paid API.
 */
internal class CameraMicGuard(private val context: Context) {

    private val preferences = ProtectionPreferences(context)
    private var lastCameraAlertAt = 0L
    private var lastMicAlertAt = 0L

    /**
     * Probe whether a foreground package is using camera or microphone
     * right now. Returns alerts to be acted on by the caller.
     */
    fun probe(packageName: String): List<MediaAccessAlert> = runCatching {
        if (!preferences.enabled || !preferences.cameraMicGuardEnabled) return@runCatching emptyList()
        if (packageName.isBlank() || packageName == context.packageName) return@runCatching emptyList()
        if (packageName == "android") return@runCatching emptyList()
        val info = context.packageManager.getPackageInfo(packageName, 0) ?: return@runCatching emptyList()
        if (isSystemApp(info)) return@runCatching emptyList()
        val ops = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val alerts = mutableListOf<MediaAccessAlert>()
        val cameraAllowed = checkOpNoThrow(ops, OPSTR_CAMERA, packageName)
        val micAllowed = checkOpNoThrow(ops, OPSTR_AUDIO_RECORD, packageName)
        val now = System.currentTimeMillis()
        if (cameraAllowed && now - lastCameraAlertAt > ALERT_COOLDOWN_MS) {
            lastCameraAlertAt = now
            preferences.totalCameraMicAlerts = preferences.totalCameraMicAlerts + 1
            alerts += MediaAccessAlert(packageName, MediaKind.CAMERA)
        }
        if (micAllowed && now - lastMicAlertAt > ALERT_COOLDOWN_MS) {
            lastMicAlertAt = now
            preferences.totalCameraMicAlerts = preferences.totalCameraMicAlerts + 1
            alerts += MediaAccessAlert(packageName, MediaKind.MICROPHONE)
        }
        alerts
    }.getOrDefault(emptyList())

    private fun checkOpNoThrow(ops: AppOpsManager, op: String, packageName: String): Boolean =
        runCatching {
            ops.unsafeCheckOpNoThrow(op, android.os.Process.myUid(), packageName) == AppOpsManager.MODE_ALLOWED
        }.getOrDefault(false)

    private fun isSystemApp(info: android.content.pm.PackageInfo): Boolean =
        (info.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) ?: 0) != 0

    companion object {
        private const val OP_CAMERA = 26
        private const val OP_AUDIO_RECORD = 27
        private const val OPSTR_CAMERA = "android:camera"
        private const val OPSTR_AUDIO_RECORD = "android:record_audio"
        private const val ALERT_COOLDOWN_MS = 15_000L
    }
}

internal enum class MediaKind { CAMERA, MICROPHONE }

internal data class MediaAccessAlert(
    val packageName: String,
    val kind: MediaKind
)
