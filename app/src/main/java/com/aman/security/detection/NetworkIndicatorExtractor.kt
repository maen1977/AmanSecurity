package com.aman.security.detection

object NetworkIndicatorExtractor {
    data class Result(
        val urls: Set<String>,
        val domains: Set<String>,
        val ips: Set<String>
    )

    fun extract(text: String, maxIndicators: Int = 64): Result {
        if (text.isEmpty()) return Result(emptySet(), emptySet(), emptySet())
        val urls = linkedSetOf<String>()
        val domains = linkedSetOf<String>()
        val ips = linkedSetOf<String>()

        URL.findAll(text).forEach { match ->
            if (urls.size < maxIndicators) urls += match.value.take(1024)
        }
        DOMAIN.findAll(text).forEach { match ->
            if (domains.size < maxIndicators) domains += match.value.lowercase().trimEnd('.')
        }
        IPV4.findAll(text).forEach { match ->
            val candidate = match.value
            if (ips.size < maxIndicators && candidate.split('.').all { octet ->
                    octet.toIntOrNull()?.let { it in 0..255 } == true
                }) {
                ips += candidate
            }
        }
        return Result(urls, domains, ips)
    }

    private val URL = Regex("https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]{4,1024}", RegexOption.IGNORE_CASE)
    private val DOMAIN = Regex("(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,24}(?![A-Za-z0-9_-])")
    private val IPV4 = Regex("(?<![A-Za-z0-9])(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![A-Za-z0-9])")
}
