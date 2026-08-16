package com.aman.security.runtime

import android.content.Context
import android.os.Build
import android.provider.Settings
import com.aman.security.R

/**
 * System hardening auditor: detects device-level conditions that
 * advanced spyware uses to hide, including active USB debugging,
 * enabled developer options, mock-location apps and root markers.
 *
 * Fully on-device checks using public Android APIs. Commercial
 * suites surface the same signals in their device-security reports.
 */
public class SystemHardeningAuditor(private val context: Context) {

    fun audit(): HardeningReport {
        val findings = mutableListOf<HardeningFinding>()
        if (isUsbDebuggingActive()) {
            findings += HardeningFinding(HardeningKind.USB_DEBUGGING, R.string.runtime_hardening_usb_debug)
        }
        if (isDeveloperOptionsEnabled()) {
            findings += HardeningFinding(HardeningKind.DEVELOPER_OPTIONS, R.string.runtime_hardening_dev_options)
        }
        if (isMockLocationAppActive()) {
            findings += HardeningFinding(HardeningKind.MOCK_LOCATION, R.string.runtime_hardening_mock_location)
        }
        if (hasRootMarkers()) {
            findings += HardeningFinding(HardeningKind.ROOT_MARKERS, R.string.runtime_hardening_root)
        }
        if (hasAccessibilityAbusers()) {
            findings += HardeningFinding(HardeningKind.ACCESSIBILITY_ABUSE, R.string.runtime_hardening_accessibility)
        }
        return HardeningReport(findings)
    }

    private fun isUsbDebuggingActive(): Boolean =
        Settings.Secure.getInt(context.contentResolver, Settings.Secure.ADB_ENABLED, 0) == 1

    private fun isDeveloperOptionsEnabled(): Boolean =
        Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1

    private fun isMockLocationAppActive(): Boolean =
        runCatching {
            Settings.Secure.getString(context.contentResolver, "mock_location")
        }.getOrNull().isNullOrBlank().not()

    private fun hasRootMarkers(): Boolean {
        val candidates = listOf("/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su")
        return candidates.any { runCatching { java.io.File(it).exists() }.getOrDefault(false) }
    }

    private fun hasAccessibilityAbusers(): Boolean {
        val enabled = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return false
        if (enabled.isBlank()) return false
        val services = enabled.split(':').filter { it.isNotBlank() }
        val ownPackage = context.packageName
        // Sideload-safe: any accessibility service not belonging to this app is reported.
        return services.any { !it.startsWith("$ownPackage/") }
    }
}

public enum class HardeningKind {
    USB_DEBUGGING, DEVELOPER_OPTIONS, MOCK_LOCATION, ROOT_MARKERS, ACCESSIBILITY_ABUSE
}

public data class HardeningFinding(
    val kind: HardeningKind,
    val explanationRes: Int
)

data class HardeningReport(
    val findings: List<HardeningFinding>
) {
    val isHardened: Boolean get() = findings.isEmpty()
    val score: Int
        get() = 100 - (findings.size * 20).coerceIn(0, 100)
}
