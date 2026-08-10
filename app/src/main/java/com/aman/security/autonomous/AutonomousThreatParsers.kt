package com.aman.security.autonomous

import java.net.IDN
import java.util.Locale

object AutonomousThreatParsers {
    private val sampleLink = Regex("(?i)/sample/([a-f0-9]{64})/")
    private val domainRegex = Regex("(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}")
    private val ipv4Regex = Regex("\\\"ip_address\\\"\\s*:\\s*\\\"((?:\\d{1,3}\\.){3}\\d{1,3})\\\"")
    private val patchRegex = Regex("20\\d{2}-\\d{2}-(?:01|05)")
    private val cveRegex = Regex("CVE-20\\d{2}-\\d{4,8}", RegexOption.IGNORE_CASE)

    fun malwareBazaarAndroidHashes(text: String): Set<String> = sampleLink.findAll(text)
        .map { it.groupValues[1].lowercase(Locale.ROOT) }.toCollection(linkedSetOf())

    fun phishingHosts(text: String): Set<String> = domainRegex.findAll(text)
        .mapNotNull { normalizeHost(it.value) }
        .filterNot { it == "api.destroy.tools" || it.endsWith(".destroy.tools") }
        .toCollection(linkedSetOf())

    fun feodoIps(text: String): Set<String> = ipv4Regex.findAll(text)
        .map { it.groupValues[1] }
        .filter(::validIpv4)
        .toCollection(linkedSetOf())

    fun latestAndroidPatch(text: String): String? = patchRegex.findAll(text).map { it.value }.maxOrNull()

    fun cves(text: String): Set<String> = cveRegex.findAll(text).map { it.value.uppercase(Locale.ROOT) }.toSet()

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
