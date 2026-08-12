package com.aman.security.security

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.TrafficStats
import android.text.format.Formatter
import com.aman.security.R
import com.aman.security.protection.ProtectionActivityKind
import com.aman.security.protection.ProtectionActivityState
import com.aman.security.protection.ProtectionActivityStore
import com.aman.security.protection.ProtectionNotifier
import com.aman.security.protection.ProtectionPreferences
import com.aman.security.web.RecentDnsObservationCache


data class DataExfiltrationFinding(
    val appName: String,
    val packageName: String,
    val uid: Int,
    val backgroundTxBytes: Long,
    val foregroundTxBytes: Long,
    val recentDnsHostCount: Int,
    val assessment: DataExfiltrationAssessment
)

data class DataExfiltrationSummary(
    val checkedAt: Long,
    val auditedUids: Int,
    val reviewCount: Int,
    val highCount: Int,
    val findings: List<DataExfiltrationFinding>,
    val detailedAuditRan: Boolean,
    val usageAccessAvailable: Boolean
)

/**
 * Lightweight local data-exfiltration guard.
 *
 * The normal heartbeat performs one O(1) device TX counter read. A more expensive
 * NetworkStatsManager query runs only after a meaningful upload burst, on the periodic safety
 * interval, or when the user explicitly asks for a check. No packet payloads are inspected and
 * no network metadata leaves the phone.
 */
class DataExfiltrationGuard(private val context: Context) {
    private val preferences = ProtectionPreferences(context)
    private val activityStore = ProtectionActivityStore(context)
    private val packageManager = context.packageManager

    fun lightweightHeartbeat(now: Long = System.currentTimeMillis()): DataExfiltrationSummary? {
        if (!preferences.enabled || !preferences.dataExfiltrationGuardEnabled || !DataExfiltrationAccess.isGranted(context)) {
            return null
        }
        val totalTx = TrafficStats.getTotalTxBytes()
        if (totalTx == TrafficStats.UNSUPPORTED) return null

        val previousTx = preferences.lastDataExfilDeviceTxBytes
        val previousProbeAt = preferences.lastDataExfilProbeAt
        preferences.lastDataExfilDeviceTxBytes = totalTx
        preferences.lastDataExfilProbeAt = now

        val delta = if (previousTx > 0L && totalTx >= previousTx) totalTx - previousTx else 0L
        val probeSpan = if (previousProbeAt > 0L) now - previousProbeAt else 0L
        val periodicDue = preferences.lastDataExfilDetailedAuditAt <= 0L ||
            now - preferences.lastDataExfilDetailedAuditAt >= PERIODIC_DETAILED_AUDIT_MS
        val burst = probeSpan > 0L && delta >= QUICK_UPLOAD_TRIGGER_BYTES
        if (!periodicDue && !burst) return DataExfiltrationSummary(
            checkedAt = now,
            auditedUids = 0,
            reviewCount = preferences.lastDataExfilReviewCount,
            highCount = preferences.lastDataExfilHighCount,
            findings = emptyList(),
            detailedAuditRan = false,
            usageAccessAvailable = true
        )
        return audit(now)
    }

    fun audit(now: Long = System.currentTimeMillis()): DataExfiltrationSummary {
        if (!DataExfiltrationAccess.isGranted(context)) {
            return DataExfiltrationSummary(now, 0, 0, 0, emptyList(), false, false)
        }
        val start = now - AUDIT_WINDOW_MS
        val usage = collectUsage(start, now)
        val privileged = runCatching { PrivilegedAccessAuditor(context).audit().byPackage() }.getOrDefault(emptyMap())
        val spywareAuditor = SpywareAuditor(context)
        val findings = mutableListOf<DataExfiltrationFinding>()

        for ((uid, sample) in usage) {
            if (uid <= 0 || uid == context.applicationInfo.uid || sample.backgroundTxBytes < MIN_CANDIDATE_BACKGROUND_BYTES) continue
            val packages = packageManager.getPackagesForUid(uid).orEmpty().distinct()
            for (packageName in packages) {
                if (packageName == context.packageName) continue
                val appInfo = applicationInfo(packageName) ?: continue
                val systemApp = isSystemApp(appInfo)
                val spyware = runCatching { spywareAuditor.auditPackage(packageName)?.assessment }.getOrNull()
                val signals = spyware?.signals.orEmpty()
                val privilegedKinds = privileged[packageName]?.kinds.orEmpty()
                val privilegedCount = maxOf(
                    privilegedKinds.size,
                    listOf(
                        SpywareCapabilitySignal.ACCESSIBILITY_SERVICE,
                        SpywareCapabilitySignal.NOTIFICATION_LISTENER,
                        SpywareCapabilitySignal.DEVICE_ADMIN
                    ).count(signals::contains)
                )
                val surveillanceCount = listOf(
                    SpywareCapabilitySignal.SMS_ACCESS,
                    SpywareCapabilitySignal.CALL_LOG_ACCESS,
                    SpywareCapabilitySignal.LOCATION_ACCESS,
                    SpywareCapabilitySignal.MICROPHONE_ACCESS,
                    SpywareCapabilitySignal.CONTACTS_ACCESS
                ).count(signals::contains)
                val sideloaded = SpywareCapabilitySignal.SIDELOADED in signals || privileged[packageName]?.sideloaded == true
                val persistent = SpywareCapabilitySignal.BOOT_PERSISTENCE in signals
                val dnsHosts = RecentDnsObservationCache.distinctHostCount(uid, start, now)
                val assessment = DataExfiltrationPolicy.evaluate(
                    DataExfiltrationInput(
                        backgroundTxBytes = sample.backgroundTxBytes,
                        foregroundTxBytes = sample.foregroundTxBytes,
                        sideloaded = sideloaded,
                        privilegedControlCount = privilegedCount,
                        surveillanceSignalCount = surveillanceCount,
                        persistent = persistent,
                        recentDnsHostCount = dnsHosts,
                        systemApp = systemApp
                    )
                )
                if (assessment.level == DataExfiltrationLevel.CLEAR) continue
                val label = runCatching { packageManager.getApplicationLabel(appInfo).toString() }
                    .getOrDefault(packageName).ifBlank { packageName }
                findings += DataExfiltrationFinding(
                    appName = label,
                    packageName = packageName,
                    uid = uid,
                    backgroundTxBytes = sample.backgroundTxBytes,
                    foregroundTxBytes = sample.foregroundTxBytes,
                    recentDnsHostCount = dnsHosts,
                    assessment = assessment
                )
            }
        }

        val sorted = findings.distinctBy { it.packageName }
            .sortedWith(compareByDescending<DataExfiltrationFinding> { it.assessment.level }.thenByDescending { it.backgroundTxBytes })
        val high = sorted.filter { it.assessment.level == DataExfiltrationLevel.HIGH }
        val review = sorted.filter { it.assessment.level == DataExfiltrationLevel.REVIEW }
        val previousTopPackage = preferences.lastDataExfilTopPackage
        val previousCheckAt = preferences.lastDataExfilCheckAt

        preferences.lastDataExfilDetailedAuditAt = now
        preferences.lastDataExfilCheckAt = now
        preferences.lastDataExfilReviewCount = review.size
        preferences.lastDataExfilHighCount = high.size
        preferences.lastDataExfilTopPackage = sorted.firstOrNull()?.packageName
        preferences.lastDataExfilTopBytes = sorted.firstOrNull()?.backgroundTxBytes ?: 0L

        sorted.take(MAX_TIMELINE_FINDINGS).forEach { finding ->
            val uploaded = Formatter.formatFileSize(context, finding.backgroundTxBytes)
            val state = if (finding.assessment.level == DataExfiltrationLevel.HIGH) {
                ProtectionActivityState.THREAT
            } else ProtectionActivityState.ATTENTION
            activityStore.add(
                kind = ProtectionActivityKind.DATA_EXFILTRATION,
                state = state,
                title = context.getString(
                    if (finding.assessment.level == DataExfiltrationLevel.HIGH) R.string.timeline_data_exfil_high
                    else R.string.timeline_data_exfil_review,
                    finding.appName
                ),
                detail = context.getString(
                    R.string.timeline_data_exfil_detail,
                    uploaded,
                    finding.recentDnsHostCount,
                    finding.assessment.score
                ),
                dedupeKey = "${ProtectionActivityKind.DATA_EXFILTRATION}:${context.getString(if (finding.assessment.level == DataExfiltrationLevel.HIGH) R.string.timeline_data_exfil_high else R.string.timeline_data_exfil_review, finding.appName)}:${context.getString(R.string.timeline_data_exfil_detail, uploaded, finding.recentDnsHostCount, finding.assessment.score)}"
            )
        }
        high.firstOrNull()?.let { finding ->
            if (finding.packageName != previousTopPackage || now - previousCheckAt >= HIGH_ALERT_DEDUPE_MS) {
                ProtectionNotifier.notifyDataExfiltration(context, finding)
            }
        }
        if (sorted.isEmpty()) preferences.markActivity(context.getString(R.string.activity_data_exfil_clean))
        else preferences.markActivity(context.getString(R.string.activity_data_exfil_review, sorted.size))
        ProtectionNotifier.updateProtectionStatus(context)

        return DataExfiltrationSummary(
            checkedAt = now,
            auditedUids = usage.size,
            reviewCount = review.size,
            highCount = high.size,
            findings = sorted,
            detailedAuditRan = true,
            usageAccessAvailable = true
        )
    }

    @Suppress("DEPRECATION")
    private fun collectUsage(start: Long, end: Long): Map<Int, UidUsage> {
        val manager = context.getSystemService(NetworkStatsManager::class.java) ?: return emptyMap()
        val totals = linkedMapOf<Int, UidUsage>()
        listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE).forEach { networkType ->
            val stats = runCatching { manager.querySummary(networkType, null, start, end) }.getOrNull() ?: return@forEach
            stats.useSafely { networkStats ->
                val bucket = NetworkStats.Bucket()
                while (networkStats.hasNextBucket()) {
                    if (!networkStats.getNextBucket(bucket)) break
                    val uid = bucket.uid
                    if (uid <= 0) continue
                    val value = totals.getOrPut(uid) { UidUsage() }
                    if (bucket.state == NetworkStats.Bucket.STATE_FOREGROUND) {
                        value.foregroundTxBytes += bucket.txBytes.coerceAtLeast(0L)
                    } else {
                        value.backgroundTxBytes += bucket.txBytes.coerceAtLeast(0L)
                    }
                }
            }
        }
        return totals
    }

    private fun applicationInfo(packageName: String): ApplicationInfo? = runCatching {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            packageManager.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION") packageManager.getApplicationInfo(packageName, 0)
        }
    }.getOrNull()

    private fun isSystemApp(info: ApplicationInfo): Boolean =
        info.flags and ApplicationInfo.FLAG_SYSTEM != 0 || info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0

    private data class UidUsage(
        var backgroundTxBytes: Long = 0L,
        var foregroundTxBytes: Long = 0L
    )

    private inline fun NetworkStats.useSafely(block: (NetworkStats) -> Unit) {
        try {
            block(this)
        } finally {
            runCatching { close() }
        }
    }

    companion object {
        private const val MIB = 1024L * 1024L
        const val QUICK_UPLOAD_TRIGGER_BYTES = 8L * MIB
        const val PERIODIC_DETAILED_AUDIT_MS = 6L * 60L * 60L * 1000L
        const val AUDIT_WINDOW_MS = 6L * 60L * 60L * 1000L
        private const val MIN_CANDIDATE_BACKGROUND_BYTES = 8L * MIB
        private const val MAX_TIMELINE_FINDINGS = 3
        private const val HIGH_ALERT_DEDUPE_MS = 60L * 60L * 1000L
    }
}
