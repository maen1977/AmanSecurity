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
    REMOTE_ACCESS_REQUEST,
    APP_INSTALL_REQUEST,
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
        if (containsAny(lower, REMOTE_ACCESS_TERMS)) {
            signals += MessageRiskSignal.REMOTE_ACCESS_REQUEST
            score += 25
        }
        if (containsAny(lower, APP_INSTALL_TERMS)) {
            signals += MessageRiskSignal.APP_INSTALL_REQUEST
            score += 18
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
        if (urls.any { it.riskLevel == UrlRiskLevel.KNOWN_PHISHING || it.riskLevel == UrlRiskLevel.KNOWN_MALICIOUS || it.riskLevel == UrlRiskLevel.KNOWN_C2 }) {
            signals += MessageRiskSignal.KNOWN_THREAT_URL
            return MessageScanResult(text, MessageRiskLevel.KNOWN_THREAT, 100, signals, urls)
        }
        if (urls.any { it.riskLevel == UrlRiskLevel.HIGH || it.riskLevel == UrlRiskLevel.REVIEW }) {
            signals += MessageRiskSignal.SUSPICIOUS_URL
            score += if (urls.any { it.riskLevel == UrlRiskLevel.HIGH }) 40 else 22
        }

        // Remote-control and installation requests become materially riskier when
        // combined with pressure or credential/payment language.
        if (MessageRiskSignal.REMOTE_ACCESS_REQUEST in signals &&
            (MessageRiskSignal.URGENT_LANGUAGE in signals ||
                MessageRiskSignal.CREDENTIAL_REQUEST in signals ||
                MessageRiskSignal.PAYMENT_REQUEST in signals)
        ) score += 15
        if (MessageRiskSignal.APP_INSTALL_REQUEST in signals && urls.isNotEmpty()) score += 8

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
            "عاجل", "فوراً", "فورا", "حالاً", "حالا", "آخر تحذير", "ينتهي اليوم", "خلال 24", "آخر فرصة", "قبل الإقفال"
        )
        private val CREDENTIAL_TERMS = setOf(
            "password", "passcode", "otp", "one-time code", "verification code", "verify your account",
            "sign in", "login", "كلمة المرور", "رمز التحقق", "رمز الدخول", "تحقق من الحساب", "تسجيل الدخول",
            "رقم البطاقة", "كود التفعيل", "أدخل الرمز", "أدخل الرمز المؤقت"
        )
        private val PAYMENT_TERMS = setOf(
            "bank", "banking", "payment", "wallet", "credit card", "debit card", "transfer", "refund", "invoice",
            "rural bank", "money transfer", "bank account frozen", "blocked account", "suspended account",
            "بنك", "حساب بنكي", "محفظة", "بطاقة", "تحويل", "استرداد", "فاتورة", "دفع", "الحساب معلق",
            "تجميد الحساب", "حسابك مغلق", "تحويل مبالغ", "أموالك في خطر", "أموالك محمية"
        )
        private val PRIZE_TERMS = setOf(
            "winner", "you won", "prize", "gift", "free reward", "claim now", "مبروك", "ربحت", "جائزة", "هدية", "استلم الآن"
        )
        private val IMPERSONATION_TERMS = setOf(
            "support team", "security team", "administrator", "police", "customs", "tax office", "customer service",
            "central bank", "postal service", "delivery service", "ministry", "government", "identity verification",
            "update your identity", "dhl", "aramex", "fedex",
            "دعم", "فريق الأمان", "فريق الامن", "الإدارة", "الشرطة", "الجمارك", "الضريبة", "خدمة العملاء",
            "البنك المركزي", "دائرة البريد", "مصلحة الجمارك", "الوزارة", "الحكومة", "تحديث الهوية",
            "تحديث بياناتك", "توصيل", "شركة شحن", "رقم الهوية"
        )
        private val REMOTE_ACCESS_TERMS = setOf(
            "anydesk", "teamviewer", "rustdesk", "quick support", "remote support", "screen share",
            "share your screen", "remote access", "install support app", "الدعم عن بعد", "تحكم عن بعد",
            "مشاركة الشاشة", "شارك شاشتك", "تطبيق الدعم"
        )
        private val APP_INSTALL_TERMS = setOf(
            "install this app", "download this app", "install apk", "download apk", "open the apk",
            ".apk", "تثبيت التطبيق", "نزّل التطبيق", "نزل التطبيق", "حمل التطبيق", "حمّل التطبيق", "ملف apk"
        )
    }
}
