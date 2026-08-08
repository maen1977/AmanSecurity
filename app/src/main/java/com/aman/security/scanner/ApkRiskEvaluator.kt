package com.aman.security.scanner

object ApkRiskEvaluator {
    fun evaluate(signals: Set<ApkRiskSignal>): ApkRiskEvaluation {
        var score = 0

        signals.forEach { signal ->
            score += when (signal) {
                ApkRiskSignal.ACCESSIBILITY_SERVICE -> 22
                ApkRiskSignal.DEVICE_ADMIN_RECEIVER -> 20
                ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE -> 12
                ApkRiskSignal.VPN_SERVICE -> 5
                ApkRiskSignal.OVERLAY_PERMISSION -> 15
                ApkRiskSignal.REQUEST_INSTALL_PACKAGES -> 16
                ApkRiskSignal.SMS_ACCESS -> 12
                ApkRiskSignal.CONTACTS_ACCESS -> 5
                ApkRiskSignal.CALL_LOG_ACCESS -> 8
                ApkRiskSignal.MICROPHONE -> 4
                ApkRiskSignal.CAMERA -> 4
                ApkRiskSignal.PRECISE_LOCATION -> 4
                ApkRiskSignal.BOOT_START -> 5
                ApkRiskSignal.QUERY_ALL_PACKAGES -> 5
                ApkRiskSignal.DEBUGGABLE -> 6
                ApkRiskSignal.NATIVE_CODE -> 2
                ApkRiskSignal.MANY_DEX_FILES -> 3
                ApkRiskSignal.DYNAMIC_CODE_LOADING -> 7
                ApkRiskSignal.RUNTIME_EXECUTION -> 6
                ApkRiskSignal.SMS_API -> 4
                ApkRiskSignal.DEVICE_IDENTIFIER_API -> 4
            }
        }

        if (ApkRiskSignal.ACCESSIBILITY_SERVICE in signals && ApkRiskSignal.OVERLAY_PERMISSION in signals) score += 25
        if (ApkRiskSignal.ACCESSIBILITY_SERVICE in signals && ApkRiskSignal.REQUEST_INSTALL_PACKAGES in signals) score += 25
        if (ApkRiskSignal.DEVICE_ADMIN_RECEIVER in signals && ApkRiskSignal.BOOT_START in signals) score += 10
        if (
            ApkRiskSignal.SMS_ACCESS in signals &&
            ApkRiskSignal.CONTACTS_ACCESS in signals &&
            ApkRiskSignal.BOOT_START in signals
        ) score += 15
        if (ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE in signals && ApkRiskSignal.OVERLAY_PERMISSION in signals) score += 10
        if (ApkRiskSignal.DYNAMIC_CODE_LOADING in signals && ApkRiskSignal.RUNTIME_EXECUTION in signals) score += 8
        if (ApkRiskSignal.SMS_ACCESS in signals && ApkRiskSignal.SMS_API in signals) score += 5

        val bounded = score.coerceIn(0, 100)
        val level = when {
            bounded >= 55 -> ApkRiskLevel.HIGH
            bounded >= 20 -> ApkRiskLevel.REVIEW
            else -> ApkRiskLevel.LOW
        }
        return ApkRiskEvaluation(bounded, level, signals)
    }
}
