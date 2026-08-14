package com.aman.security.scanner

enum class MessageRiskLevel {
    INVALID,
    LOW,
    REVIEW,
    HIGH,
    KNOWN_THREAT
}

enum class MessageRiskSignal {
    URGENT_LANGUAGE,
    CREDENTIAL_REQUEST,
    PAYMENT_REQUEST,
    PRIZE_OR_GIFT,
    IMPERSONATION,
    SHORTENED_URL,
    MULTIPLE_URLS,
    SUSPICIOUS_URL,
    KNOWN_THREAT_URL
}

data class MessageScanResult(
    val originalText: String,
    val riskLevel: MessageRiskLevel,
    val riskScore: Int,
    val signals: Set<MessageRiskSignal>,
    val urls: List<UrlScanResult>
)

/**
 * Privacy-first smishing review. It never sends message text outside the device and
 * deliberately reports suspicious patterns as review signals, not as proof of fraud.
 */
class MessageScanner(private val urlScanner: UrlScanner) {
    fun scan(input: String): MessageScanResult {
        val text = input.trim().take(MAX_TEXT_LENGTH)
        if (text.isBlank()) {
            return MessageScanResult(input, MessageRiskLevel.INVALID, 0, emptySet(), emptyList())
        }

        val urls = SharedUrlExtractor.allCandidates(text).map(urlScanner::scan)
        val signals = linkedSetOf<MessageRiskSignal>()
        var score = 0
        val lower = text.lowercase()

        if (containsAny(lower, URGENT_TERMS)) {
            signals += MessageRiskSignal.URGENT_LANGUAGE
            score += 15
        }
        if (containsAny(lower, CREDENTIAL_TERMS)) {
            signals += MessageRiskSignal.CREDENTIAL_REQUEST
            score += 22
        }
        if (containsAny(lower, PAYMENT_TERMS)) {
            signals += MessageRiskSignal.PAYMENT_REQUEST
            score += 20
        }
        if (containsAny(lower, PRIZE_TERMS)) {
            signals += MessageRiskSignal.PRIZE_OR_GIFT
            score += 15
        }
        if (containsAny(lower, IMPERSONATION_TERMS)) {
            signals += MessageRiskSignal.IMPERSONATION
            score += 12
        }

        if (urls.size >= 2) {
            signals += MessageRiskSignal.MULTIPLE_URLS
            score += 10
        }
        if (urls.any { isShortenedHost(it.host) }) {
            signals += MessageRiskSignal.SHORTENED_URL
            // A hidden destination deserves review, but is not proof of phishing.
            score += 25
        }
        if (urls.any { it.riskLevel == UrlRiskLevel.KNOWN_PHISHING || it.riskLevel == UrlRiskLevel.KNOWN_MALICIOUS }) {
            signals += MessageRiskSignal.KNOWN_THREAT_URL
            return MessageScanResult(text, MessageRiskLevel.KNOWN_THREAT, 100, signals, urls)
        }
        if (urls.any { it.riskLevel == UrlRiskLevel.HIGH || it.riskLevel == UrlRiskLevel.REVIEW }) {
            signals += MessageRiskSignal.SUSPICIOUS_URL
            score += if (urls.any { it.riskLevel == UrlRiskLevel.HIGH }) 40 else 22
        }

        score = score.coerceAtMost(100)
        val level = when {
            score >= 65 -> MessageRiskLevel.HIGH
            score >= 25 -> MessageRiskLevel.REVIEW
            else -> MessageRiskLevel.LOW
        }
        return MessageScanResult(text, level, score, signals, urls)
    }

    private fun isShortenedHost(host: String?): Boolean {
        val value = host?.lowercase() ?: return false
        return SHORTENER_HOSTS.any { value == it || value.endsWith(".$it") }
    }

    private fun containsAny(value: String, terms: Set<String>): Boolean = terms.any(value::contains)

    companion object {
        private const val MAX_TEXT_LENGTH = 4096
        private val SHORTENER_HOSTS = setOf(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy"
        )
        private val URGENT_TERMS = setOf(
            "urgent", "act now", "immediately", "last warning", "within 24", "expires today",
            "عاجل", "فوراً", "فورا", "حالاً", "حالا", "آخر تحذير", "ينتهي اليوم", "خلال 24"
        )
        private val CREDENTIAL_TERMS = setOf(
            "password", "passcode", "otp", "one-time code", "verification code", "verify your account",
            "sign in", "login", "كلمة المرور", "رمز التحقق", "رمز الدخول", "تحقق من الحساب", "تسجيل الدخول"
        )
        private val PAYMENT_TERMS = setOf(
            "bank", "banking", "payment", "wallet", "credit card", "debit card", "transfer", "refund", "invoice",
            "بنك", "حساب بنكي", "محفظة", "بطاقة", "تحويل", "استرداد", "فاتورة", "دفع"
        )
        private val PRIZE_TERMS = setOf(
            "winner", "you won", "prize", "gift", "free reward", "claim now", "مبروك", "ربحت", "جائزة", "هدية", "استلم الآن"
        )
        private val IMPERSONATION_TERMS = setOf(
            "support team", "security team", "administrator", "police", "customs", "tax office",
            "دعم", "فريق الأمان", "فريق الامن", "الإدارة", "الشرطة", "الجمارك", "الضريبة"
        )
    }
}
