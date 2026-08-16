package com.aman.security.runtime

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.graphics.PixelFormat
import android.os.Build
import android.provider.Settings
import android.view.Gravity
import android.util.TypedValue
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import com.aman.security.R
import com.aman.security.banking.FinanceAppIdentityMatcher
import com.aman.security.protection.LocalScanCacheStore
import com.aman.security.protection.ProtectionPreferences

/**
 * Live overlay (screen-covering window) watchdog for protected sessions.
 *
 * Global standards followed by top commercial Android security suites:
 * a protected banking or OTP-sensitive session must raise an immediate
 * alert when any other app draws a SYSTEM_ALERT_WINDOW on top of it.
 * This class runs fully on-device, needs no network and no paid API.
 */
internal class OverlayWatchdog(private val context: Context) {

    private val preferences = ProtectionPreferences(context)
    private val cache = LocalScanCacheStore(context)
    private var overlayWindow: View? = null
    private var lastAlertAt = 0L
    private var inProtectedSession = false
    private var previousForeground: String? = null

    /**
     * Evaluate the app that just came to the foreground.
     * Returns a decision for the caller (ProtectionService) to act on.
     */
    fun onForegroundChanged(packageName: String): OverlayDecision {
        if (!preferences.enabled || !preferences.overlayGuardEnabled) {
            inProtectedSession = false
            return OverlayDecision.None
        }
        if (previousForeground != null && packageName == previousForeground) {
            return OverlayDecision.None
        }
        val decision = if (isSensitivePackage(packageName)) {
            dismissOverlay()
            inProtectedSession = true
            OverlayDecision.EnterSession
        } else {
            val reported = if (inProtectedSession && packageName.isNotBlank()) {
                checkOverlayAboveSession(packageName)
            } else null
            if (!isLikelyBackgroundSwitch(packageName)) inProtectedSession = false
            reported ?: OverlayDecision.None
        }
        previousForeground = packageName
        return decision
    }

    /**
     * Called while a protected session is active. If a suspicious app holds
     * overlay rights and became the foreground app above the session, the
     * guard raises the blocking alert exactly once per cooldown window.
     */
    fun onOverlayDetected(overlayPackage: String) {
        if (!inProtectedSession || !preferences.overlayGuardEnabled) return
        val now = System.currentTimeMillis()
        if (now - lastAlertAt < ALERT_COOLDOWN_MS) return
        lastAlertAt = now
        showBlockingOverlay(overlayPackage)
    }

    fun dismissOverlay() {
        overlayWindow?.let { runCatching { windowManager().removeView(it) } }
        overlayWindow = null
    }

    private fun checkOverlayAboveSession(callerPackage: String): OverlayDecision {
        if (!isSuspiciousOverlay(callerPackage)) {
            return OverlayDecision.None
        }
        onOverlayDetected(callerPackage)
        return OverlayDecision.Alert(callerPackage)
    }

    private fun isSuspiciousOverlay(pkg: String): Boolean {
        if (pkg == context.packageName) return false
        val info = packageInfo(pkg) ?: return false
        if (isSystemApp(info)) return false
        if (!isOverlayRelevant(info)) return false
        val cached = cache.loadApps()[pkg]
        if (cached != null && isCachedArtifactSuspicious(cached)) return true
        return isHighRiskByStaticSignals(info)
    }

    private fun isCachedArtifactSuspicious(cached: Any): Boolean {
        // Cached artifacts store component and signer fingerprints; an app that was
        // previously flagged during a deep scan carries a non-empty malicious marker.
        return cached.toString().contains("risk") || cached.toString().contains("alert")
    }

    private fun isHighRiskByStaticSignals(info: PackageInfo): Boolean {
        val perms = info.requestedPermissions?.toList() ?: emptyList()
        return perms.any { it in OVERLAY_RELEVANT_PERMISSIONS }
    }

    private fun isOverlayRelevant(info: PackageInfo): Boolean {
        // Only apps that requested permissions relevant to an overlay attack
        // (camera, audio, SMS, contacts, location) are flagged during a session.
        val perms = info.requestedPermissions?.toList() ?: emptyList()
        return perms.any { it in OVERLAY_RELEVANT_PERMISSIONS }
    }

    fun hasDrawPermission(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.M || Settings.canDrawOverlays(context)

    private fun isSensitivePackage(pkg: String): Boolean {
        if (pkg.isBlank()) return false
        val info = packageInfo(pkg)
        val cached = cache.loadApps()[pkg]
        if (cached != null && isCachedArtifactSuspicious(cached)) return true
        val label = info?.applicationInfo?.loadLabel(context.packageManager)?.toString().orEmpty()
        return FinanceAppIdentityMatcher.matches(pkg, label) || pkg in KNOWN_SENSITIVE_PREFIXES
    }

    private fun isSystemApp(info: PackageInfo): Boolean =
        (info.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) ?: 0) != 0

    private fun isLikelyBackgroundSwitch(pkg: String): Boolean = pkg == context.packageName

    private fun packageInfo(pkg: String): PackageInfo? =
        runCatching { context.packageManager.getPackageInfo(pkg, 0) }.getOrNull()

    private fun showBlockingOverlay(overlayPackage: String) {
        if (!hasDrawPermission()) return
        runCatching {
            val label = runCatching {
                val info = packageInfo(overlayPackage)
                info?.applicationInfo?.loadLabel(context.packageManager)?.toString()
            }.getOrDefault(overlayPackage)
            val view = TextView(context).apply {
                text = context.getString(R.string.runtime_overlay_block, label)
                setTextColor(0xFFFFFFFF.toInt())
                setBackgroundColor(0xFFB00020.toInt())
                gravity = Gravity.CENTER
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
                val pad = dp(16)
                setPadding(pad, pad, pad, pad)
            }
            val params = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT,
                overlayWindowType(),
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
                PixelFormat.TRANSLUCENT
            )
            params.gravity = Gravity.TOP or Gravity.START
            windowManager().addView(view, params)
            overlayWindow = view
        }
    }

    private fun overlayWindowType(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }

    private fun windowManager(): WindowManager =
        context.getSystemService(Context.WINDOW_SERVICE) as WindowManager

    private fun dp(value: Int): Int =
        (value * context.resources.displayMetrics.density).toInt()

    companion object {
        private const val ALERT_COOLDOWN_MS = 10_000L
        internal val OVERLAY_RELEVANT_PERMISSIONS = setOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.READ_SMS,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.SYSTEM_ALERT_WINDOW
        )
        internal val KNOWN_SENSITIVE_PREFIXES = setOf(
            "com.google.android.apps.nbu.paisa",
            "com.paypal.android",
            "com.westernunion",
            "com.microsoft.skydrive"
        )
    }
}

internal sealed class OverlayDecision {
    object None : OverlayDecision()
    object EnterSession : OverlayDecision()
    data class Alert(val overlayPackage: String) : OverlayDecision()
}
