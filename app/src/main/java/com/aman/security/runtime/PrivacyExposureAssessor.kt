package com.aman.security.runtime

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import com.aman.security.protection.ProtectionPreferences

/**
 * On-device privacy exposure assessor.
 *
 * The strongest live signal of a stalkerware or spyware infestation is
 * not a single permission but a cluster of sensitive permissions and
 * control channels granted across apps at the same time: accessibility
 * services, device admin, notification listening, and dense sensitive
 * permission coverage. This assessor quantifies the current exposure
 * on a 0-100 score without ever uploading anything.
 */
internal class PrivacyExposureAssessor(private val context: Context) {

    private val preferences = ProtectionPreferences(context)

    /** Evaluate the current privacy exposure score (0-100). */
    fun evaluate(): PrivacyExposureVerdict = runCatching {
        val appCount = runCatching { context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS).size }.getOrDefault(0)
        if (appCount == 0) return@runCatching PrivacyExposureVerdict(score = 0, level = ExposureLevel.NONE)
        val flags = context.packageManager.getPackageInfo(context.packageName, 0).applicationInfo?.flags ?: 0
        val opMan = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
        val accessActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && opMan != null) {
            isMonitoringActiveS(opMan)
        } else {
            false
        }
        val sensitiveCount = sensitivePermissionApps().toInt()
        val controlChannels = activeControlChannels().size

        val sensitiveScore = (sensitiveCount * SENSITIVE_WEIGHT).coerceAtMost(SENSITIVE_CAP)
        val channelScore = (controlChannels * CHANNEL_WEIGHT).coerceAtMost(CHANNEL_CAP)
        val accessScore = if (accessActive) ACCESS_POINTS else 0
        val score = (sensitiveScore + channelScore + accessScore).coerceAtMost(100)
        val level = when {
            score >= HIGH_THRESHOLD -> ExposureLevel.HIGH
            score >= REVIEW_THRESHOLD -> ExposureLevel.REVIEW
            else -> ExposureLevel.NONE
        }
        PrivacyExposureVerdict(score = score, level = level)
    }.getOrDefault(PrivacyExposureVerdict(score = 0, level = ExposureLevel.NONE))

    private fun sensitivePermissionApps(): Int {
        val packages = runCatching {
            context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }.getOrDefault(emptyList())
        var count = 0
        for (pkg in packages) {
            val requested = pkg.requestedPermissions?.toSet().orEmpty()
            if (requested.any { it in SENSITIVE_PERMISSIONS }) count++
        }
        return count
    }

    private fun activeControlChannels(): List<ChannelKind> {
        val channels = mutableListOf<ChannelKind>()
        if (hasActiveAccessibility()) channels += ChannelKind.ACCESSIBILITY
        if (hasDeviceAdmin()) channels += ChannelKind.DEVICE_ADMIN
        return channels
    }

    private fun hasActiveAccessibility(): Boolean = runCatching {
        val service = android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        )
        !service.isNullOrBlank()
    }.getOrDefault(false)

    private fun hasDeviceAdmin(): Boolean = runCatching {
        val manager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? android.app.admin.DevicePolicyManager
        manager?.activeAdmins?.isNotEmpty() ?: false
    }.getOrDefault(false)

    @androidx.annotation.RequiresApi(Build.VERSION_CODES.S)
    private fun isMonitoringActiveS(opMan: AppOpsManager): Boolean =
        runCatching {
            val method = AppOpsManager::class.java.getMethod("isMonitoringActive")
            (method.invoke(opMan) as? Boolean) ?: false
        }.getOrDefault(false)

    companion object {
        private val SENSITIVE_PERMISSIONS = setOf(
            Manifest.permission.READ_SMS,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.READ_CALL_LOG,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
        private const val SENSITIVE_WEIGHT = 2
        private const val SENSITIVE_CAP = 40
        private const val CHANNEL_WEIGHT = 25
        private const val CHANNEL_CAP = 50
        private const val ACCESS_POINTS = 20
        private const val HIGH_THRESHOLD = 60
        private const val REVIEW_THRESHOLD = 25
    }
}

internal enum class ChannelKind { ACCESSIBILITY, DEVICE_ADMIN }

internal enum class ExposureLevel { NONE, REVIEW, HIGH }

internal data class PrivacyExposureVerdict(val score: Int, val level: ExposureLevel)
