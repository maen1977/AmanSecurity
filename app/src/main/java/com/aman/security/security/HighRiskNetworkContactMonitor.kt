package com.aman.security.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.aman.security.R
import com.aman.security.protection.ProtectionActivityKind
import com.aman.security.protection.ProtectionActivityState
import com.aman.security.protection.ProtectionActivityStore
import com.aman.security.protection.ProtectionNotifier
import com.aman.security.protection.ProtectionPreferences
import java.util.LinkedHashMap

/**
 * Immediate, DNS-event-driven correlation for the strongest local spyware cases.
 * It does not infer that data was transferred. It only alerts when an already HIGH,
 * non-system spyware-capability app initiates a DNS-resolved network contact.
 */
class HighRiskNetworkContactMonitor(private val context: Context) {
    private val packageManager = context.packageManager
    private val preferences = ProtectionPreferences(context)
    private val activityStore = ProtectionActivityStore(context)
    private val spywareAuditor = SpywareAuditor(context)
    private val riskCache = object : LinkedHashMap<Int, CachedUidRisk>(32, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, CachedUidRisk>?): Boolean = size > MAX_UID_CACHE
    }
    private val alertTimes = object : LinkedHashMap<String, Long>(32, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > MAX_ALERT_CACHE
    }

    fun onDnsContact(uid: Int, host: String, now: Long = System.currentTimeMillis()) {
        if (!preferences.enabled || !preferences.dataExfiltrationGuardEnabled || uid <= 0 || isLocalHost(host)) return
        val risk = synchronized(riskCache) {
            riskCache[uid]?.takeIf { now - it.checkedAt <= RISK_CACHE_TTL_MS }
        } ?: inspectUid(uid, now).also { synchronized(riskCache) { riskCache[uid] = it } }
        val app = risk.highRiskApp ?: return
        val key = "$uid:${host.lowercase()}"
        synchronized(alertTimes) {
            val previous = alertTimes[key] ?: 0L
            if (now - previous < ALERT_DEDUPE_MS) return
            alertTimes[key] = now
        }

        activityStore.add(
            kind = ProtectionActivityKind.DATA_EXFILTRATION,
            state = ProtectionActivityState.THREAT,
            title = context.getString(R.string.timeline_high_risk_network_contact, app.appName),
            detail = context.getString(R.string.timeline_high_risk_network_contact_detail, host),
            dedupeKey = "${ProtectionActivityKind.DATA_EXFILTRATION}:${context.getString(R.string.timeline_high_risk_network_contact, app.appName)}:${context.getString(R.string.timeline_high_risk_network_contact_detail, host)}"
        )
        preferences.markActivity(context.getString(R.string.activity_high_risk_network_contact, app.appName))
        ProtectionNotifier.notifyHighRiskNetworkContact(context, app.appName, host)
    }

    private fun inspectUid(uid: Int, now: Long): CachedUidRisk {
        val high = packageManager.getPackagesForUid(uid).orEmpty().asSequence()
            .filter { it != context.packageName }
            .filterNot(::isSystemPackage)
            .mapNotNull { packageName ->
                val finding = runCatching { spywareAuditor.auditPackage(packageName) }.getOrNull() ?: return@mapNotNull null
                finding.takeIf { it.assessment.level == SpywareReviewLevel.HIGH }
            }
            .firstOrNull()
        return CachedUidRisk(high, now)
    }

    private fun isSystemPackage(packageName: String): Boolean = runCatching {
        val info = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            packageManager.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION") packageManager.getApplicationInfo(packageName, 0)
        }
        info.flags and ApplicationInfo.FLAG_SYSTEM != 0 || info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }.getOrDefault(false)

    private fun isLocalHost(host: String): Boolean {
        val normalized = host.trim().trimEnd('.').lowercase()
        return normalized == "localhost" || normalized.endsWith(".local") || normalized.endsWith(".lan") ||
            normalized.endsWith(".home") || normalized.endsWith(".arpa")
    }

    private data class CachedUidRisk(val highRiskApp: SpywareAppFinding?, val checkedAt: Long)

    companion object {
        private const val RISK_CACHE_TTL_MS = 30L * 60L * 1000L
        private const val ALERT_DEDUPE_MS = 10L * 60L * 1000L
        private const val MAX_UID_CACHE = 64
        private const val MAX_ALERT_CACHE = 128
    }
}
