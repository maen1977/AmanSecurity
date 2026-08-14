package com.aman.security.scanner

object SharedUrlExtractor {
    fun firstCandidate(text: String?): String? = allCandidates(text).firstOrNull()

    fun allCandidates(text: String?): List<String> {
        val value = text?.trim().orEmpty()
        if (value.isBlank() || value.length > MAX_TEXT_LENGTH) return emptyList()
        val explicit = HTTP_URL.findAll(value)
            .map { trimTrailingPunctuation(it.value) }
            .filter { it.isNotBlank() }
            .distinct()
            .take(MAX_URLS_PER_MESSAGE)
            .toList()
        if (explicit.isNotEmpty()) return explicit
        if (!value.any(Char::isWhitespace) && value.length <= MAX_URL_LENGTH) {
            return listOf(trimTrailingPunctuation(value))
        }
        return emptyList()
    }

    private fun trimTrailingPunctuation(value: String): String =
        value.trimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}')

    private const val MAX_TEXT_LENGTH = 4096
    private const val MAX_URL_LENGTH = 2048
    private const val MAX_URLS_PER_MESSAGE = 8
    private val HTTP_URL = Regex("https?://[^\\s<>\\\"']+", RegexOption.IGNORE_CASE)
}
