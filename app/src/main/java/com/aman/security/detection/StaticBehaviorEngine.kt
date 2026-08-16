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
        // Media surveillance: camera + microphone + precise location (classic stalkerware triplet).
        if (
            ApkRiskSignal.CAMERA in signals &&
            ApkRiskSignal.MICROPHONE in signals &&
            ApkRiskSignal.PRECISE_LOCATION in signals
        ) {
            finding("BEHAVIOR_MEDIA_SURVEILLANCE", 26, FindingConfidence.HIGH, ThreatFamily.STALKERWARE)
        }
        // OTP theft: SMS reading combined with device identifier harvesting.
        if (ApkRiskSignal.SMS_ACCESS in signals && ApkRiskSignal.DEVICE_IDENTIFIER_API in signals) {
            finding("BEHAVIOR_OTP_THEFT", 26, FindingConfidence.HIGH, ThreatFamily.BANKER)
        }
        // Banking proxy abuse: VPN service combined with accessibility reading.
        if (ApkRiskSignal.VPN_SERVICE in signals && ApkRiskSignal.ACCESSIBILITY_SERVICE in signals) {
            finding("BEHAVIOR_VPN_ACCESSIBILITY", 26, FindingConfidence.MEDIUM, ThreatFamily.BANKER)
        }
        // Persistence dropper: admin receiver with install capability and network markers.
        if (
            ApkRiskSignal.DEVICE_ADMIN_RECEIVER in signals &&
            ApkRiskSignal.REQUEST_INSTALL_PACKAGES in signals &&
            "NETWORK_CLIENT" in markers
        ) {
            finding("BEHAVIOR_ADMIN_INSTALL_PERSISTENCE", 30, FindingConfidence.HIGH, ThreatFamily.DROPPER)
        }
        // SMS exfiltration: SMS sending API with call log reading and boot persistence.
        if (
            ApkRiskSignal.SMS_API in signals &&
            ApkRiskSignal.CALL_LOG_ACCESS in signals &&
            ApkRiskSignal.BOOT_START in signals
        ) {
            finding("BEHAVIOR_SMS_EXFIL_PERSISTENCE", 26, FindingConfidence.HIGH, ThreatFamily.SPYWARE)
        }
        // Overlay + install packages: classic phishing banker overlay chain.
        if (ApkRiskSignal.OVERLAY_PERMISSION in signals && ApkRiskSignal.REQUEST_INSTALL_PACKAGES in signals) {
            finding("BEHAVIOR_OVERLAY_INSTALLER", 24, FindingConfidence.MEDIUM, ThreatFamily.BANKER)
        }
        // SIM/identity harvesting: telephony state access combined with SMS reading enables
        // SIM-swap and OTP interception attacks against banking accounts.
        if (ApkRiskSignal.TELEPHONY_STATE_API in signals && ApkRiskSignal.SMS_ACCESS in signals) {
            finding("BEHAVIOR_SIM_OTP_INTERCEPTION", 26, FindingConfidence.HIGH, ThreatFamily.BANKER)
        }
        // Billing overlay fraud: payment APIs combined with privileged UI reading is the
        // fingerprint of fake-payment overlays targeting users during transactions.
        if (ApkRiskSignal.BILLING_API in signals && ApkRiskSignal.ACCESSIBILITY_SERVICE in signals) {
            finding("BEHAVIOR_BILLING_OVERLAY_FRAUD", 26, FindingConfidence.HIGH, ThreatFamily.BANKER)
        }
        // Media-based banker profile: billing APIs combined with audio capture.
        if (ApkRiskSignal.BILLING_API in signals && ApkRiskSignal.MICROPHONE in signals) {
            finding("BEHAVIOR_BILLING_MEDIA_PROFILE", 22, FindingConfidence.MEDIUM, ThreatFamily.BANKER)
        }
        // Storage sweep: full external storage control combined with sensitive data access
        // indicates file-stealing spyware harvesting documents and images.
        if (
            ApkRiskSignal.MANAGE_EXTERNAL_STORAGE_API in signals &&
            (ApkRiskSignal.SMS_ACCESS in signals || ApkRiskSignal.CONTACTS_ACCESS in signals)
        ) {
            finding("BEHAVIOR_STORAGE_SWEEP", 22, FindingConfidence.MEDIUM, ThreatFamily.SPYWARE)
        }
        // Phone state exfiltration: line number/SIM harvesting combined with contacts access
        // is the signature of credential-theft tooling used in account takeovers.
        if (ApkRiskSignal.READ_PHONE_STATE_API in signals && ApkRiskSignal.CONTACTS_ACCESS in signals) {
            finding("BEHAVIOR_IDENTITY_EXFIL", 22, FindingConfidence.MEDIUM, ThreatFamily.SPYWARE)
        }
        return out
    }
}
