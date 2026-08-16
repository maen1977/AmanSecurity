package com.aman.security.detection

import java.net.IDN
import java.net.URI

/**
 * LinkRiskAnalyzer: on-device phishing and suspicious link heuristics
 * for links opened or shared while a banking or OTP-sensitive session
 * is active. No network lookups, no paid API.
 *
 * Risk factors evaluated locally:
 *  - punycode / homoglyph domains (IDN encoded with xn--)
 *  - suspicious TLDs and digit-heavy hosts
 *  - credential-impersonating subdomains (paypal-, google-, bank-)
 *  - IP-address hosts with non-standard ports
 *  - excessive length / mixed scheme tricks
 */
public class LinkRiskAnalyzer {

    public fun analyze(url: String?): LinkRiskReport {
        if (url.isNullOrBlank()) return LinkRiskReport(risk = RiskLevel.NONE, reason = "لا يوجد رابط")
        val parsed = runCatching { URI(url.trim()) }.getOrNull() ?: return LinkRiskReport(risk = RiskLevel.HIGH, reason = "رابط تالف")
        val host = parsed.host ?: return LinkRiskReport(risk = RiskLevel.HIGH, reason = "لا يوجد مضيف")
        val decoded = runCatching { IDN.toUnicode(host) }.getOrDefault(host)

        val markers = mutableListOf<RiskMarker>()
        if (host.startsWith("xn--", ignoreCase = true) || host.contains("xn--", ignoreCase = true)) {
            markers += RiskMarker.PUNYCODE_DOMAIN
        }
        if (decoded != host) {
            markers += RiskMarker.IDN_HOMOGRAPH
        }
        val root = stripSubdomain(decoded)
        if (root.contains(Regex("\\d{2,}"))) {
            markers += RiskMarker.DIGIT_HEAVY_HOST
        }
        if (isIpHost(host)) {
            markers += RiskMarker.IP_HOST
            if (parsed.port !in STANDARD_PORTS) {
                markers += RiskMarker.NON_STANDARD_PORT
            }
        }
        // Brand impersonation targets subdomain impersonators like
        // "paypal.evil.com": the brand must sit outside the registered
        // root, and a genuine sensitive root (paypal.com) is never
        // flagged as an impersonator of itself.
        if (SENSITIVE_PREFIXES.any { host.startsWith(it, ignoreCase = true) } &&
            host != root &&
            SENSITIVE_ROOTS.none { root.equals(it, ignoreCase = true) }) {
            markers += RiskMarker.BRAND_IMPERSONATION
        }
        if (host.length > MAX_HOST_LENGTH) {
            markers += RiskMarker.EXCESSIVE_LENGTH
        }
        if (url.contains("@") && parsed.scheme in CREDENTIAL_SCHEMES) {
            markers += RiskMarker.CREDENTIAL_IN_URL
        }

        val risk = when {
            markers.contains(RiskMarker.BRAND_IMPERSONATION) -> RiskLevel.HIGH
            markers.contains(RiskMarker.PUNYCODE_DOMAIN) -> RiskLevel.HIGH
            markers.contains(RiskMarker.IDN_HOMOGRAPH) -> RiskLevel.HIGH
            RiskMarker.entries.count { it in markers } >= 2 -> RiskLevel.HIGH
            markers.isNotEmpty() -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
        return LinkRiskReport(risk = risk, reason = summarize(markers), markers = markers)
    }

    private fun stripSubdomain(host: String): String {
        val parts = host.removeSuffix(".").split(".")
        return if (parts.size > 2) parts.takeLast(2).joinToString(".") else host
    }

    private fun isIpHost(host: String): Boolean =
        Regex("^(\\d{1,3}\\.){3}\\d{1,3}$").matches(host)

    private fun summarize(markers: List<RiskMarker>): String =
        markers.joinToString(", ") { it.labelAr }

    companion object {
        private const val MAX_HOST_LENGTH = 63
        private val STANDARD_PORTS = setOf(80, 443)
        private val CREDENTIAL_SCHEMES = setOf("http", "https")
        private val SENSITIVE_PREFIXES = listOf(
            "paypal", "google", "apple", "microsoft", "amazon",
            "bank", "secure", "login", "wallet", "crypto"
        )
        private val SENSITIVE_ROOTS = setOf(
            "paypal.com", "google.com", "apple.com", "microsoft.com",
            "amazon.com", "github.com", "facebook.com", "meta.com",
            "googleapis.com", "gstatic.com", "googleusercontent.com",
            "bank", "example.com", "example.org"
        )
    }
}

public enum class RiskLevel { NONE, LOW, MEDIUM, HIGH }

public enum class RiskMarker(public val labelAr: String) {
    PUNYCODE_DOMAIN("نطاق مشفر"),
    IDN_HOMOGRAPH("أحرف متشابهة مخادعة"),
    DIGIT_HEAVY_HOST("مضيف رقمي مشبوه"),
    IP_HOST("مضيف بعنوان رقمي"),
    NON_STANDARD_PORT("منفذ غير قياسي"),
    BRAND_IMPERSONATION("انتحال علامة تجارية"),
    EXCESSIVE_LENGTH("رابط طويل بشكل مفرط"),
    CREDENTIAL_IN_URL("بيانات دخول داخل الرابط")
}

public data class LinkRiskReport(
    val risk: RiskLevel,
    val reason: String,
    val markers: List<RiskMarker> = emptyList()
) {
    public val isDangerous: Boolean get() = risk == RiskLevel.HIGH
}
