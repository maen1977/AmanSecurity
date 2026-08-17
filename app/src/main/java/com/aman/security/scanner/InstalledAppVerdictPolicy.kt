package com.aman.security.scanner

import com.aman.security.detection.DetectionVerdictLevel
import com.aman.security.detection.MultiEngineVerdict

/**
 * Presentation policy for installed-app antivirus results.
 *
 * Capability and heuristic evidence can be useful, but it is not an identity-level malware
 * confirmation. A weak REVIEW score (the common 20..54 range, including the historical 49 cap)
 * is kept out of the installed-app threat list so ordinary official apps are not presented as
 * threats. Red remains reserved for KNOWN_THREAT; stronger non-confirmed evidence remains a
 * review item for further inspection.
 */
object InstalledAppVerdictPolicy {
    fun riskLevel(verdict: MultiEngineVerdict): AppRiskLevel = when {
        verdict.level == DetectionVerdictLevel.KNOWN_THREAT -> AppRiskLevel.KNOWN_THREAT
        verdict.score >= 55 && verdict.level in setOf(
            DetectionVerdictLevel.VERY_HIGH,
            DetectionVerdictLevel.HIGH,
            DetectionVerdictLevel.REVIEW
        ) -> AppRiskLevel.MEDIUM
        else -> AppRiskLevel.LOW
    }

    /** Compatibility helper for callers that only have a level; scores are unavailable there. */
    fun riskLevel(level: DetectionVerdictLevel): AppRiskLevel = when (level) {
        DetectionVerdictLevel.KNOWN_THREAT -> AppRiskLevel.KNOWN_THREAT
        DetectionVerdictLevel.VERY_HIGH,
        DetectionVerdictLevel.HIGH,
        DetectionVerdictLevel.REVIEW -> AppRiskLevel.MEDIUM
        DetectionVerdictLevel.LOW,
        DetectionVerdictLevel.TEST -> AppRiskLevel.LOW
    }
}
