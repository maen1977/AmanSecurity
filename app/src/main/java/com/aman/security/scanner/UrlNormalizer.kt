package com.aman.security.scanner

import java.net.IDN
import java.net.URI
import java.util.Locale

object UrlNormalizer {
    data class Normalized(
        val url: String,
        val host: String,
        val scheme: String,
        val port: Int?,
        val hasUserInfo: Boolean,
        val isIpLiteral: Boolean,
        val hasPunycode: Boolean,
        val labelCount: Int
    )

    fun normalize(input: String): Normalized? {
        val trimmed = input.trim()
        if (trimmed.isEmpty() || trimmed.length > MAX_INPUT_LENGTH) return null
        if (trimmed.any { it == '\u0000' || it == '\r' || it == '\n' || it == '\t' }) return null

        val withScheme = when {
            trimmed.startsWith("//") -> "https:$trimmed"
            SCHEME_REGEX.containsMatchIn(trimmed) -> trimmed
            else -> "https://$trimmed"
        }

        val uri = runCatching { URI(withScheme) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return null
        if (scheme != "http" && scheme != "https") return null
        val authority = uri.rawAuthority ?: return null
        if (authority.isBlank()) return null

        val authorityParts = parseAuthority(authority) ?: return null
        val rawHost = authorityParts.host.trim().removeSuffix(".")
        if (rawHost.isBlank()) return null

        val ipv6 = rawHost.contains(':')
        val asciiHost = if (ipv6) {
            rawHost.lowercase(Locale.ROOT)
        } else {
            runCatching { IDN.toASCII(rawHost, IDN.USE_STD3_ASCII_RULES) }.getOrNull()
                ?.lowercase(Locale.ROOT)
                ?: return null
        }
        if (!ipv6 && (asciiHost.length > 253 || asciiHost.split('.').any { it.isBlank() || it.length > 63 })) return null

        val port = authorityParts.port
        if (port != null && port !in 1..65535) return null
        val includePort = port != null && !((scheme == "http" && port == 80) || (scheme == "https" && port == 443))

        val hostForUrl = if (ipv6) "[$asciiHost]" else asciiHost
        val normalizedPath = normalizePath(uri.rawPath)
        val query = uri.rawQuery?.let { "?$it" }.orEmpty()
        val portText = if (includePort) ":$port" else ""
        val normalizedUrl = "$scheme://$hostForUrl$portText$normalizedPath$query"

        return Normalized(
            url = normalizedUrl,
            host = asciiHost,
            scheme = scheme,
            port = if (includePort) port else null,
            hasUserInfo = authorityParts.hasUserInfo,
            isIpLiteral = isIpLiteral(asciiHost),
            hasPunycode = asciiHost.split('.').any { it.startsWith("xn--") },
            labelCount = if (ipv6) 1 else asciiHost.split('.').size
        )
    }

    private data class AuthorityParts(val host: String, val port: Int?, val hasUserInfo: Boolean)

    private fun parseAuthority(authority: String): AuthorityParts? {
        val at = authority.lastIndexOf('@')
        val hasUserInfo = at >= 0
        val hostPort = if (hasUserInfo) authority.substring(at + 1) else authority
        if (hostPort.isBlank()) return null

        if (hostPort.startsWith("[")) {
            val close = hostPort.indexOf(']')
            if (close <= 1) return null
            val host = hostPort.substring(1, close)
            val suffix = hostPort.substring(close + 1)
            val port = when {
                suffix.isEmpty() -> null
                suffix.startsWith(":") -> suffix.substring(1).toIntOrNull() ?: return null
                else -> return null
            }
            return AuthorityParts(host, port, hasUserInfo)
        }

        val colon = hostPort.lastIndexOf(':')
        if (colon > 0 && hostPort.indexOf(':') == colon) {
            val portText = hostPort.substring(colon + 1)
            if (portText.isNotEmpty() && portText.all(Char::isDigit)) {
                return AuthorityParts(hostPort.substring(0, colon), portText.toIntOrNull() ?: return null, hasUserInfo)
            }
        }
        return AuthorityParts(hostPort, null, hasUserInfo)
    }

    private fun normalizePath(rawPath: String?): String {
        val path = rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        return if (path.startsWith('/')) path else "/$path"
    }

    private fun isIpLiteral(host: String): Boolean {
        if (host.contains(':')) return host.matches(Regex("^[0-9a-fA-F:.]+$"))
        val parts = host.split('.')
        return parts.size == 4 && parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit) && (part.toIntOrNull() ?: 256) in 0..255
        }
    }

    private val SCHEME_REGEX = Regex("^[A-Za-z][A-Za-z0-9+.-]*:")
    private const val MAX_INPUT_LENGTH = 4096
}
