package com.aman.security.detection

import com.aman.security.scanner.ApkRiskSignal

/**
 * Conservative zero-day heuristics. A single generic marker never produces a high verdict.
 * Findings require capability chains or hidden executable payload evidence.
 */
object ZeroDayHeuristicEngine {
    fun evaluate(profile: ZeroDayProfile): List<DetectionFinding> {
        val out = mutableListOf<DetectionFinding>()
        val s = profile.signals
        val m = profile.markers

        fun add(id: String, score: Int, confidence: FindingConfidence, family: ThreatFamily) {
            out += DetectionFinding(id, DetectionSource.ZERO_DAY_HEURISTIC, score, confidence, family)
        }

        if (profile.hiddenDexPayloadCount > 0 &&
            (ApkRiskSignal.DYNAMIC_CODE_LOADING in s || "DYNAMIC_CODE" in m)) {
            add("ZERO_DAY_HIDDEN_DEX_LOADER", 32, FindingConfidence.HIGH, ThreatFamily.DROPPER)
        }
        if (profile.hiddenElfPayloadCount > 0 && "NATIVE_LOAD" in m && "NETWORK_CLIENT" in m) {
            add("ZERO_DAY_HIDDEN_NATIVE_NETWORK", 30, FindingConfidence.HIGH, ThreatFamily.TROJAN)
        }
        if (profile.nestedArchivePayloadCount > 0 && "DOWNLOADER" in m && "INSTALLER_API" in m) {
            add("ZERO_DAY_NESTED_INSTALL_CHAIN", 28, FindingConfidence.HIGH, ThreatFamily.DROPPER)
        }
        if (profile.highEntropyAssetCount >= 2 && "DYNAMIC_CODE" in m && "HEAVY_REFLECTION" in m) {
            add("ZERO_DAY_ENCRYPTED_DYNAMIC_PAYLOAD", 24, FindingConfidence.MEDIUM, ThreatFamily.DROPPER)
        }
        if ("ANTI_DEBUG" in m && "EMULATOR_CHECK" in m && "PACKER_PRESENT" in m) {
            add("ZERO_DAY_ANTI_ANALYSIS_PACKED", 20, FindingConfidence.MEDIUM, ThreatFamily.RISKWARE)
        }
        if ("ANTI_DEBUG" in m && "EMULATOR_CHECK" in m && "HIDE_COMPONENT" in m && "NETWORK_CLIENT" in m) {
            add("ZERO_DAY_STEALTH_ANTI_ANALYSIS", 30, FindingConfidence.HIGH, ThreatFamily.TROJAN)
        }
        if ("ACCESSIBILITY_NODE" in m && "WEBVIEW_BRIDGE" in m &&
            ApkRiskSignal.SMS_ACCESS in s && "NETWORK_CLIENT" in m) {
            add("ZERO_DAY_BANKER_INTERACTION_CHAIN", 28, FindingConfidence.HIGH, ThreatFamily.BANKER)
        }
        if ("DEVICE_ID" in m && "COMMAND_EXEC" in m && "NETWORK_CLIENT" in m &&
            ApkRiskSignal.BOOT_START in s) {
            add("ZERO_DAY_REMOTE_IMPLANT_CHAIN", 30, FindingConfidence.HIGH, ThreatFamily.RAT)
        }
        // Hidden payload plus stealth markers: encrypted dropper without dynamic markers.
        if (profile.hiddenElfPayloadCount > 0 && "HIDE_COMPONENT" in m && "PACKER_PRESENT" in m) {
            add("ZERO_DAY_STEALTH_NATIVE_PAYLOAD", 28, FindingConfidence.HIGH, ThreatFamily.TROJAN)
        }
        // Accessibility-driven banking fraud combined with overlay display capability.
        if ("ACCESSIBILITY_NODE" in m && ApkRiskSignal.OVERLAY_PERMISSION in s &&
            ApkRiskSignal.SMS_API in s && "NETWORK_CLIENT" in m) {
            add("ZERO_DAY_OVERLAY_BANKER_CHAIN", 28, FindingConfidence.HIGH, ThreatFamily.BANKER)
        }
        // Screen capture abuse: capture capability plus command execution channel.
        if ("SCREEN_CAPTURE" in m && "COMMAND_EXEC" in m && "NETWORK_CLIENT" in m) {
            add("ZERO_DAY_SCREEN_EXFIL_CHAIN", 26, FindingConfidence.HIGH, ThreatFamily.RAT)
        }
        // Notification harvesting plus identifier collection without user-facing reason.
        if (ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE in s && "DEVICE_ID" in m && "NETWORK_CLIENT" in m) {
            add("ZERO_DAY_NOTIFICATION_EXFIL", 20, FindingConfidence.MEDIUM, ThreatFamily.SPYWARE)
        }
        return out
    }
}
