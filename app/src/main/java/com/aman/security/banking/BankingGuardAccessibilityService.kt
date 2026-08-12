package com.aman.security.banking

import android.accessibilityservice.AccessibilityService
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent
import com.aman.security.R
import com.aman.security.protection.ProtectionActivityKind
import com.aman.security.protection.ProtectionActivityState
import com.aman.security.protection.ProtectionActivityStore
import com.aman.security.protection.ProtectionNotifier
import com.aman.security.protection.ProtectionPreferences
import com.aman.security.security.privilegedAccessLabel
import java.util.concurrent.Executors

/**
 * Optional, event-driven banking protection. It observes package transitions only;
 * it does not request or read window content, typed text, passwords or account data.
 */
class BankingGuardAccessibilityService : AccessibilityService() {
    private lateinit var preferences: ProtectionPreferences
    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile private var lastPackage: String? = null
    @Volatile private var lastCheckAt: Long = 0L

    override fun onServiceConnected() {
        super.onServiceConnected()
        preferences = ProtectionPreferences(this)
        preferences.bankingAccessibilityHeartbeatAt = System.currentTimeMillis()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (!::preferences.isInitialized || !preferences.enabled || !preferences.bankingProtectionEnabled) return
        if (event?.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        val packageName = event.packageName?.toString()?.takeIf { it.isNotBlank() } ?: return
        if (packageName == this.packageName) return
        if (!isProtectedBankingPackage(packageName)) return

        val now = System.currentTimeMillis()
        if (packageName == lastPackage && now - lastCheckAt < CHECK_DEDUPE_MS) return
        lastPackage = packageName
        lastCheckAt = now
        preferences.bankingAccessibilityHeartbeatAt = now

        executor.execute {
            val assessment = runCatching { BankingRiskEvaluator(applicationContext).evaluate(packageName) }.getOrNull() ?: return@execute
            mainHandler.post { handleAssessment(assessment) }
        }
    }

    override fun onInterrupt() = Unit

    override fun onDestroy() {
        if (::preferences.isInitialized) preferences.bankingAccessibilityHeartbeatAt = 0L
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun isProtectedBankingPackage(packageName: String): Boolean {
        if (packageName in preferences.protectedBankingPackages) return true
        return preferences.autoProtectFinanceApps && BankingAppDetector.isFinanceCategory(this, packageName)
    }

    private fun handleAssessment(assessment: BankingRiskAssessment) {
        if (!::preferences.isInitialized || !preferences.enabled || !preferences.bankingProtectionEnabled) return
        preferences.lastBankingCheckAt = System.currentTimeMillis()
        preferences.lastBankingRiskLevel = assessment.level.name
        val timeline = ProtectionActivityStore(this)
        when (assessment.level) {
            BankingRiskLevel.SAFE -> {
                timeline.add(
                    kind = ProtectionActivityKind.BANKING_GUARD,
                    state = ProtectionActivityState.SAFE,
                    title = getString(R.string.timeline_banking_safe),
                    detail = assessment.targetPackage,
                    dedupeKey = "banking:safe:${assessment.targetPackage}"
                )
            }
            BankingRiskLevel.REVIEW -> {
                timeline.add(
                    kind = ProtectionActivityKind.BANKING_GUARD,
                    state = ProtectionActivityState.ATTENTION,
                    title = getString(R.string.timeline_banking_review),
                    detail = bankingRiskDetail(assessment)
                )
                ProtectionNotifier.notifyBankingRisk(this, assessment, blocked = false)
            }
            BankingRiskLevel.BLOCK -> {
                val blocked = preferences.blockBankingOnHighRisk
                if (blocked) performGlobalAction(GLOBAL_ACTION_HOME)
                timeline.add(
                    kind = ProtectionActivityKind.BANKING_GUARD,
                    state = ProtectionActivityState.THREAT,
                    title = getString(if (blocked) R.string.timeline_banking_blocked else R.string.timeline_banking_high_risk),
                    detail = bankingRiskDetail(assessment)
                )
                ProtectionNotifier.notifyBankingRisk(this, assessment, blocked = blocked)
            }
        }
        preferences.markActivity(getString(R.string.activity_banking_checked))
    }

    private fun bankingRiskDetail(assessment: BankingRiskAssessment): String = buildString {
        if (assessment.rootSignals > 0) append(getString(R.string.banking_root_signal_detail, assessment.rootSignals))
        assessment.riskyApps.take(3).forEach { app ->
            if (isNotEmpty()) append(" • ")
            append(app.appName)
            append(": ")
            append(app.kinds.joinToString { privilegedAccessLabel(it) })
        }
    }

    companion object {
        private const val CHECK_DEDUPE_MS = 30_000L
    }
}
