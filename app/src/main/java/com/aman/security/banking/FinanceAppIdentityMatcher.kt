package com.aman.security.banking

/**
 * Pure, offline finance-app identity hint used only to decide when Banking Guard should
 * perform an extra safety check. A match never marks an app as malicious and never
 * changes the malware verdict.
 */
internal object FinanceAppIdentityMatcher {
    private val exactTokens = setOf(
        "bank", "banking", "wallet", "finance", "financial", "fintech",
        "payment", "payments", "money", "cash", "crypto",
        "بنك", "مصرف", "محفظة", "دفع", "تمويل", "مالي", "مالية"
    )

    private val tokenRegex = Regex("[\\p{L}\\p{N}]+")

    fun matches(packageName: String, label: String): Boolean {
        val packageTokens = packageName
            .lowercase()
            .split('.', '_', '-')
            .filter { it.isNotBlank() }
        val labelTokens = tokenRegex.findAll(label.lowercase()).map { it.value }.toList()
        val tokens = packageTokens + labelTokens

        return tokens.any { rawToken ->
            val token = rawToken.removeArabicDefiniteArticle()
            token in exactTokens ||
                token.startsWith("bank") || token.endsWith("bank") ||
                token == "pay" || token.startsWith("paypal")
        }
    }

    private fun String.removeArabicDefiniteArticle(): String =
        if (startsWith("ال") && length > 3) removePrefix("ال") else this
}
