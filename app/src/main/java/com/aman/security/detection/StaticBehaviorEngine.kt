package com.aman.security.detection

import com.aman.security.scanner.ApkRiskSignal

object StaticBehaviorEngine {
    fun evaluate(signals: Set<ApkRiskSignal>, markers: Set<String>): List<DetectionFinding> {
        val out = mutableListOf<DetectionFinding>()

        fun finding(id: String, score: Int, confidence: FindingConfidence, family: ThreatFamily) {
            out += DetectionFinding(id, DetectionSource.STATIC_BEHAVIOR, score, confidence, family)
        }

        if (ApkRiskSignal.ACCESSIBILITY_SERVICE in signals && ApkRiskSignal.OVERLAY_PERMISSION in signals) {
            finding("BEHAVIOR_ACCESSIBILITY_OVERLAY", 28, FindingConfidence.HIGH, ThreatFamily.BANKER)
        }
        if (
            ApkRiskSignal.SMS_ACCESS in signals &&
            ApkRiskSignal.CONTACTS_ACCESS in signals &&
            ApkRiskSignal.BOOT_START in signals
        ) {
            finding("BEHAVIOR_SMS_CONTACTS_PERSISTENCE", 28, FindingConfidence.HIGH, ThreatFamily.SPYWARE)
        }
        if (
            ApkRiskSignal.MICROPHONE in signals &&
            ApkRiskSignal.PRECISE_LOCATION in signals &&
            ApkRiskSignal.BOOT_START in signals
        ) {
            finding("BEHAVIOR_TRACKING_SURVEILLANCE", 24, FindingConfidence.MEDIUM, ThreatFamily.STALKERWARE)
        }
        if (
            ApkRiskSignal.DYNAMIC_CODE_LOADING in signals &&
            ApkRiskSignal.REQUEST_INSTALL_PACKAGES in signals
        ) {
            finding("BEHAVIOR_DYNAMIC_DROPPER", 30, FindingConfidence.HIGH, ThreatFamily.DROPPER)
        }
        if (
            ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE in signals &&
            ApkRiskSignal.ACCESSIBILITY_SERVICE in signals
        ) {
            finding("BEHAVIOR_NOTIFICATION_ACCESSIBILITY", 24, FindingConfidence.HIGH, ThreatFamily.BANKER)
        }
        if ("SCREEN_CAPTURE" in markers && "ACCESSIBILITY_ACTIONS" in markers) {
            finding("BEHAVIOR_SCREEN_CONTROL", 25, FindingConfidence.MEDIUM, ThreatFamily.RAT)
        }
        if ("CLIPBOARD_READ" in markers && "NETWORK_CLIENT" in markers) {
            finding("BEHAVIOR_CLIPBOARD_EXFIL", 18, FindingConfidence.MEDIUM, ThreatFamily.SPYWARE)
        }
        if ("COMMAND_EXEC" in markers && "NETWORK_CLIENT" in markers && "BOOT_PERSISTENCE" in markers) {
            finding("BEHAVIOR_REMOTE_CONTROL_CHAIN", 32, FindingConfidence.HIGH, ThreatFamily.RAT)
        }
        if ("FILE_ENCRYPTION" in markers && "MASS_FILE_ACCESS" in markers) {
            finding("BEHAVIOR_FILE_ENCRYPTION_CHAIN", 18, FindingConfidence.MEDIUM, ThreatFamily.RANSOMWARE)
        }
        return out
    }
}
