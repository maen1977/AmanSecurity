package com.aman.security.protection

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aman.security.R
import com.aman.security.security.IntrusionChangeSeverity
import com.aman.security.security.IntrusionMonitor
import com.aman.security.security.integrityChangeLabel
import com.aman.security.security.privilegedAccessLabel

/** Six-hour, low-cost review of changes to privileged Android control surfaces. */
class IntrusionMonitorWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : Worker(appContext, workerParams) {
    override fun doWork(): Result {
        val prefs = ProtectionPreferences(applicationContext)
        if (!prefs.enabled || !prefs.intrusionMonitorEnabled) return Result.success()

        return runCatching {
            val summary = IntrusionMonitor(applicationContext).check()
            prefs.lastIntrusionCheckAt = System.currentTimeMillis()
            prefs.lastIntrusionReviewCount = summary.reviewChanges
            prefs.lastIntrusionHighCount = summary.highChanges

            val timeline = ProtectionActivityStore(applicationContext)
            when {
                summary.baselineCreated -> timeline.add(
                    kind = ProtectionActivityKind.INTRUSION_MONITOR,
                    state = ProtectionActivityState.INFO,
                    title = applicationContext.getString(R.string.timeline_intrusion_baseline),
                    detail = applicationContext.getString(
                        R.string.timeline_intrusion_baseline_detail,
                        summary.scannedPrivilegedApps
                    ),
                    dedupeKey = "intrusion:baseline"
                )
                summary.totalChanges == 0 -> timeline.add(
                    kind = ProtectionActivityKind.INTRUSION_MONITOR,
                    state = ProtectionActivityState.SAFE,
                    title = applicationContext.getString(R.string.timeline_intrusion_clean),
                    detail = applicationContext.getString(R.string.timeline_intrusion_clean_detail),
                    dedupeKey = "intrusion:clean"
                )
                else -> {
                    val state = if (summary.highChanges > 0) ProtectionActivityState.THREAT else ProtectionActivityState.ATTENTION
                    timeline.add(
                        kind = ProtectionActivityKind.INTRUSION_MONITOR,
                        state = state,
                        title = applicationContext.getString(R.string.timeline_intrusion_change, summary.totalChanges),
                        detail = buildList {
                            addAll(summary.changes.take(3).map { change ->
                                "${change.appName}: ${change.addedKinds.joinToString { applicationContext.privilegedAccessLabel(it) }}"
                            })
                            addAll(summary.integrityChanges.take(2).map { applicationContext.integrityChangeLabel(it.kind) })
                        }.joinToString(" • ")
                    )
                    ProtectionNotifier.notifyIntrusionChange(applicationContext, summary)
                }
            }
            prefs.markActivity(applicationContext.getString(R.string.activity_intrusion_checked))
            Result.success()
        }.getOrElse { Result.retry() }
    }
}
