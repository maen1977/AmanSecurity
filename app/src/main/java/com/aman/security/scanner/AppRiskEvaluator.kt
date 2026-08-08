package com.aman.security.scanner

object AppRiskEvaluator {
    private const val READ_SMS = "android.permission.READ_SMS"
    private const val RECEIVE_SMS = "android.permission.RECEIVE_SMS"
    private const val SEND_SMS = "android.permission.SEND_SMS"
    private const val READ_CONTACTS = "android.permission.READ_CONTACTS"
    private const val READ_CALL_LOG = "android.permission.READ_CALL_LOG"
    private const val WRITE_CALL_LOG = "android.permission.WRITE_CALL_LOG"
    private const val RECORD_AUDIO = "android.permission.RECORD_AUDIO"
    private const val CAMERA = "android.permission.CAMERA"
    private const val ACCESS_FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION"
    private const val RECEIVE_BOOT_COMPLETED = "android.permission.RECEIVE_BOOT_COMPLETED"
    private const val SYSTEM_ALERT_WINDOW = "android.permission.SYSTEM_ALERT_WINDOW"
    private const val REQUEST_INSTALL_PACKAGES = "android.permission.REQUEST_INSTALL_PACKAGES"

    fun evaluate(input: AppRiskInput): AppRiskEvaluation {
        if (input.knownThreatReference != null) {
            return AppRiskEvaluation(
                score = 100,
                level = AppRiskLevel.KNOWN_THREAT,
                signals = collectSignals(input)
            )
        }

        val signals = collectSignals(input)
        var score = 0

        if (AppRiskSignal.ACCESSIBILITY_SERVICE in signals) score += 24
        if (AppRiskSignal.OVERLAY in signals) score += 14
        if (AppRiskSignal.INSTALL_PACKAGES in signals) score += 14
        if (AppRiskSignal.SMS_ACCESS in signals) score += 12
        if (AppRiskSignal.CONTACTS_ACCESS in signals) score += 7
        if (AppRiskSignal.CALL_LOG_ACCESS in signals) score += 10
        if (AppRiskSignal.MICROPHONE in signals) score += 6
        if (AppRiskSignal.CAMERA in signals) score += 4
        if (AppRiskSignal.PRECISE_LOCATION in signals) score += 5
        if (AppRiskSignal.BOOT_START in signals) score += 5
        if (AppRiskSignal.NON_STORE_INSTALL in signals) score += 10

        // Combinations matter more than isolated permissions. These remain risk indicators,
        // never proof that an application is malicious.
        if (AppRiskSignal.ACCESSIBILITY_SERVICE in signals && AppRiskSignal.OVERLAY in signals) score += 18
        if (AppRiskSignal.ACCESSIBILITY_SERVICE in signals && AppRiskSignal.INSTALL_PACKAGES in signals) score += 18
        if (AppRiskSignal.SMS_ACCESS in signals && AppRiskSignal.CONTACTS_ACCESS in signals) score += 14
        if (AppRiskSignal.SMS_ACCESS in signals && AppRiskSignal.BOOT_START in signals) score += 8
        if (AppRiskSignal.MICROPHONE in signals && AppRiskSignal.PRECISE_LOCATION in signals && AppRiskSignal.BOOT_START in signals) score += 10

        val boundedScore = score.coerceIn(0, 99)
        val level = when {
            boundedScore >= 55 -> AppRiskLevel.HIGH
            boundedScore >= 20 -> AppRiskLevel.MEDIUM
            else -> AppRiskLevel.LOW
        }
        return AppRiskEvaluation(boundedScore, level, signals)
    }

    private fun collectSignals(input: AppRiskInput): Set<AppRiskSignal> {
        val permissions = input.requestedPermissions
        val signals = linkedSetOf<AppRiskSignal>()

        if (input.hasAccessibilityService) signals += AppRiskSignal.ACCESSIBILITY_SERVICE
        if (SYSTEM_ALERT_WINDOW in permissions) signals += AppRiskSignal.OVERLAY
        if (REQUEST_INSTALL_PACKAGES in permissions) signals += AppRiskSignal.INSTALL_PACKAGES
        if (permissions.any { it == READ_SMS || it == RECEIVE_SMS || it == SEND_SMS }) signals += AppRiskSignal.SMS_ACCESS
        if (READ_CONTACTS in permissions) signals += AppRiskSignal.CONTACTS_ACCESS
        if (permissions.any { it == READ_CALL_LOG || it == WRITE_CALL_LOG }) signals += AppRiskSignal.CALL_LOG_ACCESS
        if (RECORD_AUDIO in permissions) signals += AppRiskSignal.MICROPHONE
        if (CAMERA in permissions) signals += AppRiskSignal.CAMERA
        if (ACCESS_FINE_LOCATION in permissions) signals += AppRiskSignal.PRECISE_LOCATION
        if (RECEIVE_BOOT_COMPLETED in permissions) signals += AppRiskSignal.BOOT_START
        if (input.installSource == AppInstallSource.LOCAL_FILE || input.installSource == AppInstallSource.DOWNLOADED_FILE || input.installSource == AppInstallSource.UNKNOWN) {
            signals += AppRiskSignal.NON_STORE_INSTALL
        }
        return signals
    }
}
