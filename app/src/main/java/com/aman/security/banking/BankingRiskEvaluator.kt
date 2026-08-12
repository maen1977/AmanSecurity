package com.aman.security.banking

import android.content.Context
import android.os.Build
import com.aman.security.security.DeviceSecurityAuditor
import com.aman.security.security.PrivilegedAccessApp
import com.aman.security.security.PrivilegedAccessAuditor
import com.aman.security.security.PrivilegedAccessKind
import com.aman.security.security.SpywareAuditor
import com.aman.security.security.SpywareReviewLevel

enum class BankingRiskLevel {
    SAFE,
    REVIEW,
    BLOCK
}

data class BankingRiskApp(
    val appName: String,
    val packageName: String,
    val kinds: Set<PrivilegedAccessKind>,
    val sideloaded: Boolean,
    val level: BankingRiskLevel
)

data class BankingRiskAssessment(
    val targetPackage: String,
    val level: BankingRiskLevel,
    val riskyApps: List<BankingRiskApp>,
    val rootSignals: Int
)

/**
 * Conservative banking-session policy. It never blocks merely because another app has
 * one sensitive permission. BLOCK requires an active privileged-control combination,
 * normally with confirmed sideloading or a high spyware-capability assessment.
 */
class BankingRiskEvaluator(private val context: Context) {
    fun evaluate(targetPackage: String): BankingRiskAssessment {
        val snapshot = PrivilegedAccessAuditor(context).audit()
        val spyware = SpywareAuditor(context)
        val risks = snapshot.apps.mapNotNull { app ->
            if (app.packageName == context.packageName || app.packageName == targetPackage || app.systemApp) {
                return@mapNotNull null
            }
            val spywareAssessment = spyware.auditPackage(app.packageName)?.assessment
            val level = classify(app, spywareAssessment?.level)
            if (level == BankingRiskLevel.SAFE) null else BankingRiskApp(
                appName = app.appName,
                packageName = app.packageName,
                kinds = app.kinds,
                sideloaded = app.sideloaded,
                level = level
            )
        }.sortedWith(
            compareByDescending<BankingRiskApp> { it.level }
                .thenByDescending { it.kinds.size }
        )
        val rootSignals = DeviceSecurityAuditor(context).audit().rootSignals
        val level = when {
            risks.any { it.level == BankingRiskLevel.BLOCK } -> BankingRiskLevel.BLOCK
            risks.isNotEmpty() || rootSignals > 0 -> BankingRiskLevel.REVIEW
            else -> BankingRiskLevel.SAFE
        }
        return BankingRiskAssessment(targetPackage, level, risks, rootSignals)
    }

    private fun classify(app: PrivilegedAccessApp, spywareLevel: SpywareReviewLevel?): BankingRiskLevel {
        val accessibility = PrivilegedAccessKind.ACCESSIBILITY in app.kinds
        val admin = PrivilegedAccessKind.DEVICE_ADMIN in app.kinds
        val listener = PrivilegedAccessKind.NOTIFICATION_LISTENER in app.kinds
        val overlay = PrivilegedAccessKind.OVERLAY in app.kinds
        val controllerCount = listOf(accessibility, admin, listener).count { it }

        return when {
            spywareLevel == SpywareReviewLevel.HIGH && (accessibility || admin || listener) -> BankingRiskLevel.BLOCK
            app.sideloaded && (accessibility || admin) && (overlay || listener) -> BankingRiskLevel.BLOCK
            app.sideloaded && controllerCount >= 2 -> BankingRiskLevel.BLOCK
            (accessibility && overlay) || (admin && overlay) || controllerCount >= 2 -> BankingRiskLevel.REVIEW
            spywareLevel == SpywareReviewLevel.REVIEW && controllerCount >= 1 -> BankingRiskLevel.REVIEW
            else -> BankingRiskLevel.SAFE
        }
    }
}

object BankingAppDetector {
    /**
     * Android's ApplicationInfo categories do not expose a finance/banking category.
     * Keep automatic protection local and conservative by using only the installed
     * application's own package/label identity. A user-selected banking package still
     * takes precedence in BankingGuardAccessibilityService.
     */
    fun isFinanceCategory(context: Context, packageName: String): Boolean = runCatching {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getApplicationInfo(
                packageName,
                android.content.pm.PackageManager.ApplicationInfoFlags.of(0)
            )
        } else {
            @Suppress("DEPRECATION") context.packageManager.getApplicationInfo(packageName, 0)
        }
        val label = context.packageManager.getApplicationLabel(info)?.toString().orEmpty()
        FinanceAppIdentityMatcher.matches(packageName, label)
    }.getOrDefault(false)
}
