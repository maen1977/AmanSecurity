package com.aman.security.autonomous

import com.aman.security.scanner.UrlNormalizer
import java.net.IDN
import java.net.URI
import java.util.Locale

object AutonomousThreatParsers {
    data class UrlIndicators(
        val urls: Set<String>,
        val hosts: Set<String>
    ) {
        val count: Int get() = urls.size + hosts.size
    }

    private val sampleLink = Regex("(?i)/sample/([a-f0-9]{64})/")
    private val domainRegex = Regex("(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}")
    private val httpUrlRegex = Regex("(?i)https?://[^\\s\\\"'<>]+")
    private val ipv4Regex = Regex("\\\"ip_address\\\"\\s*:\\s*\\\"((?:\\d{1,3}\\.){3}\\d{1,3})\\\"")
    private val patchRegex = Regex("20\\d{2}-\\d{2}-(?:01|05)")
    private val cveRegex = Regex("CVE-20\\d{2}-\\d{4,8}", RegexOption.IGNORE_CASE)

    fun malwareBazaarAndroidHashes(text: String): Set<String> = sampleLink.findAll(text)
        .map { it.groupValues[1].lowercase(Locale.ROOT) }.toCollection(linkedSetOf())

    /**
     * Parses phishing data without throwing away path-level intelligence.
     *
     * If a feed contains full URLs, Aman keeps their normalized URL forms (including a
     * query-stripped form) and only promotes a URL to a host-wide DNS indicator when the feed
     * points at the host root. That avoids blocking an entire legitimate shared host because one
     * path on it was abused. Feeds that contain only domain names retain the legacy host behavior.
     */
    fun phishingIndicators(text: String): UrlIndicators = parseWebIndicators(
        text = text,
        excludedHosts = setOf("api.destroy.tools", "openphish.com")
    )

    /** Legacy helper retained for tests/callers that explicitly need only host indicators. */
    fun phishingHosts(text: String): Set<String> = if (extractNormalizedUrls(text).isEmpty()) {
        domainRegex.findAll(text)
            .mapNotNull { normalizeHost(it.value) }
            .filterNot { it == "api.destroy.tools" || it.endsWith(".destroy.tools") }
            .toCollection(linkedSetOf())
    } else {
        phishingIndicators(text).hosts
    }

    fun urlhausIndicators(text: String): UrlIndicators = parseWebIndicators(
        text = text.lineSequence().filterNot { it.trimStart().startsWith("#") }.joinToString("\n"),
        excludedHosts = setOf("urlhaus.abuse.ch")
    )

    /** Legacy host view used by existing unit tests and diagnostics. */
    fun urlhausHosts(text: String): Set<String> = text.lineSequence()
        .map(String::trim)
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .mapNotNull { line ->
            val host = runCatching { URI(line).host }.getOrNull() ?: return@mapNotNull null
            normalizeHost(host)
        }
        .toCollection(linkedSetOf())

    fun feodoIps(text: String): Set<String> = ipv4Regex.findAll(text)
        .map { it.groupValues[1] }
        .filter(::validIpv4)
        .toCollection(linkedSetOf())

    fun latestAndroidPatch(text: String): String? = patchRegex.findAll(text).map { it.value }.maxOrNull()

    fun cves(text: String): Set<String> = cveRegex.findAll(text).map { it.value.uppercase(Locale.ROOT) }.toSet()

    private fun parseWebIndicators(text: String, excludedHosts: Set<String>): UrlIndicators {
        val normalizedUrls = extractNormalizedUrls(text)
        if (normalizedUrls.isEmpty()) {
            val hosts = domainRegex.findAll(text)
                .mapNotNull { normalizeHost(it.value) }
                .filterNot { host -> excludedHosts.any { host == it || host.endsWith(".$it") } }
                .toCollection(linkedSetOf())
            return UrlIndicators(emptySet(), hosts)
        }

        val urls = linkedSetOf<String>()
        val hosts = linkedSetOf<String>()
        normalizedUrls.forEach { normalized ->
            if (excludedHosts.any { normalized.host == it || normalized.host.endsWith(".$it") }) return@forEach
            urls += normalized.url
            stripQuery(normalized.url)?.let(urls::add)
            if (isRootUrl(normalized.url)) hosts += normalized.host
        }
        return UrlIndicators(urls, hosts)
    }

    private fun extractNormalizedUrls(text: String): List<UrlNormalizer.Normalized> {
        // JSON feeds commonly escape slashes as `\/`; decoding only that harmless representation
        // is enough for URL extraction and avoids interpreting arbitrary JSON escape sequences.
        val prepared = text.replace("\\/", "/")
        return httpUrlRegex.findAll(prepared)
            .map { match -> match.value.trimEnd(',', ';', '.', ')', ']', '}') }
            .mapNotNull(UrlNormalizer::normalize)
            .distinctBy { it.url }
            .toList()
    }

    private fun stripQuery(url: String): String? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        if (uri.rawQuery == null) return null
        val path = uri.rawPath.orEmpty()
        // Query-only shorteners and shared root endpoints often use the query itself as the
        // tenant/resource key. Do not turn one malicious query into a block for every query.
        if (path.isEmpty() || path == "/") return null
        val q = url.indexOf('?')
        return if (q > 0) url.substring(0, q) else null
    }

    private fun isRootUrl(url: String): Boolean {
        val uri = runCatching { URI(url) }.getOrNull() ?: return false
        val path = uri.rawPath.orEmpty()
        return (path.isEmpty() || path == "/") && uri.rawQuery == null
    }

    private fun normalizeHost(value: String): String? {
        val raw = value.trim().trim('.').lowercase(Locale.ROOT)
        val ascii = runCatching { IDN.toASCII(raw, IDN.USE_STD3_ASCII_RULES) }.getOrNull() ?: return null
        if (ascii.length !in 4..253 || ascii.split('.').any { it.isBlank() || it.length > 63 }) return null
        return ascii
    }

    private fun validIpv4(value: String): Boolean {
        val parts = value.split('.')
        return parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all(Char::isDigit) && (p.toIntOrNull() ?: 256) in 0..255 }
    }
}
