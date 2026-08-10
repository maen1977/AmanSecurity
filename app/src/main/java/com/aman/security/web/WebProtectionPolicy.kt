package com.aman.security.web

import com.aman.security.scanner.UrlRiskLevel

enum class WebProtectionDecision {
    ALLOW,
    CAUTION,
    BLOCK,
    TEST,
    INVALID
}

object WebProtectionPolicy {
    fun decide(level: UrlRiskLevel): WebProtectionDecision = when (level) {
        UrlRiskLevel.LOW -> WebProtectionDecision.ALLOW
        UrlRiskLevel.REVIEW, UrlRiskLevel.HIGH -> WebProtectionDecision.CAUTION
        UrlRiskLevel.KNOWN_PHISHING, UrlRiskLevel.KNOWN_MALICIOUS -> WebProtectionDecision.BLOCK
        UrlRiskLevel.TEST_SIGNATURE -> WebProtectionDecision.TEST
        UrlRiskLevel.INVALID -> WebProtectionDecision.INVALID
    }

    fun mayOpenAfterWarning(level: UrlRiskLevel): Boolean = decide(level) == WebProtectionDecision.CAUTION
}
