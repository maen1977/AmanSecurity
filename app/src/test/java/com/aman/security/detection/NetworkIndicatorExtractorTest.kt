package com.aman.security.detection

import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkIndicatorExtractorTest {
    @Test
    fun extractsUrlsDomainsAndIpv4WithBounds() {
        val result = NetworkIndicatorExtractor.extract(
            "connect https://api.example.org/path and backup.example.net then 198.51.100.42 but not 999.1.1.1",
            maxIndicators = 8
        )
        assertTrue(result.urls.any { it.startsWith("https://api.example.org") })
        assertTrue("api.example.org" in result.domains)
        assertTrue("backup.example.net" in result.domains)
        assertTrue("198.51.100.42" in result.ips)
        assertTrue("999.1.1.1" !in result.ips)
        assertTrue(result.urls.size <= 8)
        assertTrue(result.domains.size <= 8)
        assertTrue(result.ips.size <= 8)
    }
}
