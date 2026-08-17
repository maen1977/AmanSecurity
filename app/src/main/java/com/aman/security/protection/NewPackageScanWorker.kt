package com.aman.security.protection

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.scanner.InstalledAppScanner
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.security.SpywareAuditor
import com.aman.security.security.SpywareCapabilitySignal
import com.aman.security.security.SpywareReviewLevel

class NewPackageScanWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : Worker(appContext, workerParams) {
    override fun doWork(): Result {
        val preferences = ProtectionPreferences(applicationContext)
        if (!preferences.enabled || !preferences.appInstallMonitorEnabled) return Result.success()
        val packageName = inputData.getString(KEY_PACKAGE_NAME)?.takeIf { it.isNotBlank() }
            ?: return Result.failure()
        if (packageName == applicationContext.packageName) return Result.success()

        return runCatching {
            val database = SignatureDatabase(applicationContext)
            val result = InstalledAppScanner(applicationContext, database).scanPackageByName(packageName)
                ?: return Result.success()
            preferences.totalAppsChecked += 1L
            preferences.markActivity(applicationContext.getString(com.aman.security.R.string.activity_app_checked, result.appName))
            val timeline = ProtectionActivityStore(applicationContext)
            val fingerprint = AppRescanPolicy.fingerprint(result)
            val previous = preferences.replaceAppFingerprint(packageName, fingerprint)
            val severity = ProtectionPolicy.severityForApp(result.riskLevel)
            if (severity != null && AppRescanPolicy.shouldNotify(previous, result)) {
                val event = ProtectionEventStore(applicationContext).add(
                    type = ProtectionEventType.APP,
                    displayName = result.appName,
                    detail = result.packageName,
                    severity = severity
                )
                ProtectionNotifier.notifyEvent(applicationContext, event)
                preferences.totalThreatsDetected += 1L
                timeline.add(
                    kind = ProtectionActivityKind.APP_SCAN,
                    state = ProtectionActivityState.THREAT,
                    title = applicationContext.getString(com.aman.security.R.string.timeline_app_threat, result.appName),
                    detail = result.packageName
                )
            } else {
                val state = when (result.riskLevel) {
                    com.aman.security.scanner.AppRiskLevel.HIGH,
                    com.aman.security.scanner.AppRiskLevel.KNOWN_THREAT -> ProtectionActivityState.ATTENTION
                    com.aman.security.scanner.AppRiskLevel.MEDIUM -> ProtectionActivityState.ATTENTION
                    else -> ProtectionActivityState.SAFE
                }
                timeline.add(
                    kind = ProtectionActivityKind.APP_SCAN,
                    state = state,
                    title = applicationContext.getString(com.aman.security.R.string.timeline_app_checked, result.appName),
                    detail = result.packageName,
                    dedupeKey = "${ProtectionActivityKind.APP_SCAN}:${applicationContext.getString(com.aman.security.R.string.timeline_app_checked, result.appName)}:${result.packageName}"
                )
            }

            val spywareReview = SpywareAuditor(applicationContext).auditPackage(packageName)
            if (spywareReview != null) {
                val sensitiveSignals = setOf(
                    SpywareCapabilitySignal.SMS_ACCESS,
                    SpywareCapabilitySignal.CALL_LOG_ACCESS,
                    SpywareCapabilitySignal.LOCATION_ACCESS,
                    SpywareCapabilitySignal.MICROPHONE_ACCESS,
                    SpywareCapabilitySignal.CONTACTS_ACCESS,
                    SpywareCapabilitySignal.CAMERA_ACCESS,
                    SpywareCapabilitySignal.PHONE_STATE_ACCESS
                )
                val sensitiveCount = spywareReview.assessment.signals.count(sensitiveSignals::contains)
                if (SpywareCapabilitySignal.SIDELOADED in spywareReview.assessment.signals && sensitiveCount >= 2) {
                    timeline.add(
                        kind = ProtectionActivityKind.SECURITY_AUDIT,
                        state = ProtectionActivityState.ATTENTION,
                        title = applicationContext.getString(
                            com.aman.security.R.string.timeline_sideload_sensitive_install,
                            spywareReview.appName
                        ),
                        detail = applicationContext.getString(
                            com.aman.security.R.string.timeline_sideload_sensitive_detail,
                            sensitiveCount
                        ),
                        dedupeKey = "sideload-sensitive:${spywareReview.packageName}"
                    )
                    ProtectionNotifier.notifySideloadedSensitiveApp(
                        applicationContext,
                        spywareReview.appName,
                        spywareReview.packageName,
                        sensitiveCount
                    )
                }
            }
            if (spywareReview != null && spywareReview.assessment.level != SpywareReviewLevel.LOW) {
                val isHighRisk = spywareReview.assessment.level == SpywareReviewLevel.HIGH
                timeline.add(
                    kind = ProtectionActivityKind.SECURITY_AUDIT,
                    // SpywareAudit is a privacy-capability review; it must not paint the
                    // antivirus threat state red, even when the strongest review level matches.
                    state = ProtectionActivityState.ATTENTION,
                    title = applicationContext.getString(com.aman.security.R.string.timeline_spyware_review, spywareReview.appName),
                    detail = applicationContext.getString(
                        com.aman.security.R.string.timeline_spyware_review_detail,
                        spywareReview.assessment.signals.size
                    ),
                    dedupeKey = "spyware:${spywareReview.packageName}:${spywareReview.assessment.level}"
                )
                if (isHighRisk) {
                    ProtectionNotifier.notifySpywareHighRisk(
                        applicationContext,
                        spywareReview.appName,
                        spywareReview.packageName,
                        spywareReview.assessment.signals.size
                    )
                }
            }
            ProtectionServiceController.refresh(applicationContext)
            Result.success()
        }.getOrElse { Result.retry() }
    }

    companion object {
        const val KEY_PACKAGE_NAME = "package_name"
    }
}
