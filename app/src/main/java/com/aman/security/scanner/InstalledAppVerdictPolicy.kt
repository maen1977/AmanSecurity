package com.aman.security.scanner

import com.aman.security.detection.DetectionVerdictLevel

/**
 * Presentation policy for installed-app antivirus results.
 *
 * Capability and heuristic evidence can be useful, but it is not an identity-level malware
 * confirmation. It therefore stays in the review bucket. Red is reserved for KNOWN_THREAT.
 */
object InstalledAppVerdictPolicy {
    fun riskLevel(level: DetectionVerdictLevel): AppRiskLevel = when (level) {
        DetectionVerdictLevel.KNOWN_THREAT -> AppRiskLevel.KNOWN_THREAT
        DetectionVerdictLevel.VERY_HIGH,
        DetectionVerdictLevel.HIGH,
        DetectionVerdictLevel.REVIEW -> AppRiskLevel.MEDIUM
        DetectionVerdictLevel.LOW,
        DetectionVerdictLevel.TEST -> AppRiskLevel.LOW
    }
}

