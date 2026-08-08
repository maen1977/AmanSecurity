package com.aman.security.scanner

object SharedUrlExtractor {
    fun firstCandidate(text: String?): String? {
        val value = text?.trim().orEmpty()
        if (value.isBlank()) return null
        HTTP_URL.find(value)?.value?.let { return trimTrailingPunctuation(it) }
        if (!value.any(Char::isWhitespace) && value.length <= 4096) return trimTrailingPunctuation(value)
        return null
    }

    private fun trimTrailingPunctuation(value: String): String = value.trimEnd('.', ',', ';', ')', ']', '}')

    private val HTTP_URL = Regex("https?://[^\\s<>\\\"']+", RegexOption.IGNORE_CASE)
}
