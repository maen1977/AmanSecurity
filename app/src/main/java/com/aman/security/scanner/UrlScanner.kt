package com.aman.security.scanner

import java.security.MessageDigest

class UrlScanner(
    private val lookup: (UrlIndicatorKind, String) -> UrlThreatIndicator?
) {
    fun scan(input: String): UrlScanResult {
        val normalized = UrlNormalizer.normalize(input)
            ?: return UrlScanResult(input, null, null, UrlRiskLevel.INVALID, 0, emptySet())

        val urlHash = sha256(normalized.url)
        val hostHash = sha256(normalized.host)
        val known = lookup(UrlIndicatorKind.URL, urlHash)
            ?: lookup(UrlIndicatorKind.HOST, hostHash)
        if (known != null) {
            val level = when (known.classification) {
                UrlThreatClassification.PHISHING -> UrlRiskLevel.KNOWN_PHISHING
                UrlThreatClassification.MALWARE -> UrlRiskLevel.KNOWN_MALICIOUS
                UrlThreatClassification.TEST_SIGNATURE -> UrlRiskLevel.TEST_SIGNATURE
            }
            return UrlScanResult(
                originalInput = input,
                normalizedUrl = normalized.url,
                host = normalized.host,
                riskLevel = level,
                riskScore = if (level == UrlRiskLevel.TEST_SIGNATURE) 0 else 100,
                signals = emptySet(),
                threatReference = known.id,
                matchedKind = known.kind
            )
        }

        val signals = linkedSetOf<UrlRiskSignal>()
        var score = 0
        if (normalized.scheme == "http") {
            signals += UrlRiskSignal.PLAIN_HTTP
            score += 5
        }
        if (normalized.isIpLiteral) {
            signals += UrlRiskSignal.IP_ADDRESS_HOST
            score += 25
        }
        if (normalized.hasPunycode) {
            signals += UrlRiskSignal.PUNYCODE_HOST
            score += 15
        }
        if (normalized.hasUserInfo) {
            signals += UrlRiskSignal.USER_INFO
            score += 35
        }
        if (normalized.port != null) {
            signals += UrlRiskSignal.NON_STANDARD_PORT
            score += 10
        }
        if (normalized.labelCount >= 5) {
            signals += UrlRiskSignal.MANY_SUBDOMAINS
            score += 10
        }
        if (normalized.url.length >= 200) {
            signals += UrlRiskSignal.LONG_URL
            score += 10
        }
        if (containsSuspiciousKeyword(normalized.url, normalized.host)) {
            signals += UrlRiskSignal.SUSPICIOUS_KEYWORDS
            score += 10
        }

        score = score.coerceAtMost(100)
        val level = when {
            score >= 55 -> UrlRiskLevel.HIGH
            score >= 20 -> UrlRiskLevel.REVIEW
            else -> UrlRiskLevel.LOW
        }
        return UrlScanResult(
            originalInput = input,
            normalizedUrl = normalized.url,
            host = normalized.host,
            riskLevel = level,
            riskScore = score,
            signals = signals
        )
    }

    private fun containsSuspiciousKeyword(url: String, host: String): Boolean {
        val lower = url.lowercase()
        val hostLower = host.lowercase()
        return SUSPICIOUS_KEYWORDS.any { keyword ->
            hostLower.contains(keyword) || lower.contains("/$keyword") || lower.contains("?$keyword") || lower.contains("&$keyword")
        }
    }

    companion object {
        fun sha256(text: String): String = MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        private val SUSPICIOUS_KEYWORDS = setOf(
            "login", "verify", "account", "password", "wallet", "payment", "secure", "auth", "banking", "update"
        )
    }
}
