package com.aman.security.security

import android.content.Context
import com.aman.security.protection.ProtectionActivityEntry
import com.aman.security.protection.ProtectionActivityKind
import com.aman.security.protection.ProtectionActivityState
import com.aman.security.protection.ProtectionActivityStore
import com.aman.security.protection.ProtectionPreferences
import com.aman.security.protection.ProtectionServiceController
import com.aman.security.web.LocalWebShieldController

data class AttackDetectionSnapshot(
    val level: AttackDetectionLevel,
    val criticalSignals: Int,
    val watchSignals: Int,
    val lastSignal: ProtectionActivityEntry?,
    val serviceHealthy: Boolean,
    val webShieldActive: Boolean,
    val intrusionMonitorActive: Boolean,
    val bankingGuardActive: Boolean,
    val dataExfiltrationGuardActive: Boolean,
    val evaluatedAt: Long
)

/**
 * Lightweight on-device attack-status aggregator.
 *
 * It does not start a worker, inspect packets, or rescan storage. It simply correlates
 * the bounded local protection timeline that the existing event-driven layers already
 * write. This keeps the Attack Detection Center effectively free while the phone is idle.
 * A blocked web domain is a WATCH signal (attempt blocked), not proof that the device was
 * compromised. Malware, high-priority privilege changes, or a banking BLOCK event are
 * CRITICAL signals until they age out of the recent-event window or the timeline is cleared.
 */
class AttackDetectionCenter(private val context: Context) {
    fun snapshot(now: Long = System.currentTimeMillis()): AttackDetectionSnapshot {
        val preferences = ProtectionPreferences(context)
        val serviceHealthy = preferences.enabled && ProtectionServiceController.isHealthy(context)
        val webShieldActive = preferences.enabled && preferences.localWebShieldEnabled &&
            LocalWebShieldController.isHealthy(context)
        val intrusionMonitorActive = preferences.enabled && preferences.intrusionMonitorEnabled
        val bankingGuardActive = preferences.enabled && preferences.bankingProtectionEnabled
        val dataExfiltrationGuardActive = preferences.enabled && preferences.dataExfiltrationGuardEnabled &&
            DataExfiltrationAccess.isGranted(context)

        val cutoff = now - RECENT_SIGNAL_WINDOW_MS
        val recentSignals = ProtectionActivityStore(context).entries()
            .asSequence()
            .filter { it.createdAt >= cutoff }
            .filter(::isAttackRelevant)
            .toList()

        val critical = recentSignals.filter(::isCritical)
        val watch = recentSignals.filter { !isCritical(it) && isWatch(it) }
        val lastSignal = (critical.asSequence() + watch.asSequence()).maxByOrNull { it.createdAt }
        val level = AttackDetectionPolicy.level(
            AttackDetectionInput(
                protectionEnabled = preferences.enabled,
                serviceHealthy = serviceHealthy,
                criticalSignals = critical.size,
                watchSignals = watch.size
            )
        )

        return AttackDetectionSnapshot(
            level = level,
            criticalSignals = critical.size,
            watchSignals = watch.size,
            lastSignal = lastSignal,
            serviceHealthy = serviceHealthy,
            webShieldActive = webShieldActive,
            intrusionMonitorActive = intrusionMonitorActive,
            bankingGuardActive = bankingGuardActive,
            dataExfiltrationGuardActive = dataExfiltrationGuardActive,
            evaluatedAt = now
        )
    }

    private fun isAttackRelevant(entry: ProtectionActivityEntry): Boolean = when (entry.kind) {
        ProtectionActivityKind.APP_SCAN,
        ProtectionActivityKind.FILE_SCAN,
        ProtectionActivityKind.DOWNLOAD_SCAN,
        ProtectionActivityKind.WEB_SHIELD,
        ProtectionActivityKind.INTRUSION_MONITOR,
        ProtectionActivityKind.BANKING_GUARD,
        ProtectionActivityKind.DATA_EXFILTRATION,
        ProtectionActivityKind.BACKGROUND_ACTIVITY,
        ProtectionActivityKind.SECURITY_AUDIT -> true
        else -> false
    }

    private fun isCritical(entry: ProtectionActivityEntry): Boolean =
        entry.state == ProtectionActivityState.THREAT && entry.kind != ProtectionActivityKind.WEB_SHIELD

    private fun isWatch(entry: ProtectionActivityEntry): Boolean =
        entry.state == ProtectionActivityState.ATTENTION ||
            (entry.kind == ProtectionActivityKind.WEB_SHIELD && entry.state == ProtectionActivityState.THREAT)

    companion object {
        const val RECENT_SIGNAL_WINDOW_MS: Long = 24L * 60L * 60L * 1000L
    }
}
