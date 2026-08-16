package com.aman.security.runtime

import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.util.Calendar

/**
 * HiddenAppDetector: finds apps that hide from the launcher (vacant
 * icons) or stay silent while performing background activity — the
 * classic camouflage technique of stalkerware and spyware.
 *
 * Pure on-device checks via public Android APIs, no network, no paid API.
 */
public class HiddenAppDetector(private val context: Context) {

    fun scan(): HiddenAppReport {
        val findings = mutableListOf<HiddenAppFinding>()
        val pm = context.packageManager
        val packages = runCatching { pm.getInstalledPackages(0) }.getOrDefault(emptyList())
        if (packages.isEmpty()) return HiddenAppReport(emptyList())

        val ownPackage = context.packageName
        for (info in packages) {
            val pkg = info.packageName ?: continue
            if (pkg == ownPackage) continue
            if (pkg.startsWith("android")) continue
            val ai = runCatching { info.applicationInfo }.getOrNull() ?: continue
            val iconRes = ai.icon != 0
            if (!iconRes && isUserApp(pkg, ai)) {
                findings += HiddenAppFinding(HiddenAppKind.VACANT_ICON, pkg)
            }
            if (isSilentBackgroundActivity(pkg) && !iconRes) {
                findings += HiddenAppFinding(HiddenAppKind.SILENT_BACKGROUND, pkg)
            }
        }
        return HiddenAppReport(findings)
    }

    private fun isUserApp(pkg: String, ai: android.content.pm.ApplicationInfo): Boolean =
        ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM == 0

    /**
     * An app that was used recently yet has no launcher icon — a
     * strong camouflage marker for hidden spyware.
     */
    private fun isSilentBackgroundActivity(pkg: String): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return false
        val mgr = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager ?: return false
        val now = System.currentTimeMillis()
        val since = now - SILENCE_WINDOW_MS
        val last = runCatching {
            mgr.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, since, now)
                .filter { it.packageName == pkg }
                .maxByOrNull { it.lastTimeUsed }?.lastTimeUsed
        }.getOrNull() ?: return false
        return last != null && now - last <= SILENCE_FRESH_MS
    }

    companion object {
        private const val SILENCE_WINDOW_MS = 24 * 60 * 60_000L
        private const val SILENCE_FRESH_MS = 60 * 60_000L
    }
}

public enum class HiddenAppKind { VACANT_ICON, SILENT_BACKGROUND }

public data class HiddenAppFinding(
    val kind: HiddenAppKind,
    val packageName: String
)

public data class HiddenAppReport(
    val findings: List<HiddenAppFinding>
) {
    val isClean: Boolean get() = findings.isEmpty()
}
