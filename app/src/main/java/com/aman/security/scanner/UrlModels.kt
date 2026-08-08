package com.aman.security.scanner

enum class UrlIndicatorKind {
    HOST,
    URL
}

enum class UrlThreatClassification {
    PHISHING,
    MALWARE,
    TEST_SIGNATURE
}

data class UrlThreatIndicator(
    val kind: UrlIndicatorKind,
    val sha256: String,
    val id: String,
    val classification: UrlThreatClassification
)

enum class UrlRiskLevel {
    LOW,
    REVIEW,
    HIGH,
    KNOWN_PHISHING,
    KNOWN_MALICIOUS,
    TEST_SIGNATURE,
    INVALID
}

enum class UrlRiskSignal {
    PLAIN_HTTP,
    IP_ADDRESS_HOST,
    PUNYCODE_HOST,
    USER_INFO,
    NON_STANDARD_PORT,
    MANY_SUBDOMAINS,
    LONG_URL,
    SUSPICIOUS_KEYWORDS
}

data class UrlScanResult(
    val originalInput: String,
    val normalizedUrl: String?,
    val host: String?,
    val riskLevel: UrlRiskLevel,
    val riskScore: Int,
    val signals: Set<UrlRiskSignal>,
    val threatReference: String? = null,
    val matchedKind: UrlIndicatorKind? = null
)
