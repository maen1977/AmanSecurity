package com.aman.security.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UrlScannerWebGuardTest {
    @Test fun parentHostMatchRespectsLabelBoundaries() {
        val badHost = "evil.example.test"
        val indicator = UrlThreatIndicator(UrlIndicatorKind.HOST, UrlScanner.sha256(badHost), "web-test", UrlThreatClassification.PHISHING)
        val scanner = UrlScanner { kind, hash -> if (kind == UrlIndicatorKind.HOST && hash == indicator.sha256) indicator else null }
        assertEquals(UrlRiskLevel.KNOWN_PHISHING, scanner.scan("https://login.evil.example.test/path").riskLevel)
        assertNull(scanner.scan("https://notexample.test/").threatReference)
    }

    @Test fun backslashAmbiguityIsRejected() {
        val scanner = UrlScanner { _, _ -> null }
        assertEquals(UrlRiskLevel.INVALID, scanner.scan("https://example.test\\@evil.test/").riskLevel)
    }

    @Test fun compoundPhishingSignalsNeedReview() {
        val scanner = UrlScanner { _, _ -> null }
        assertEquals(UrlRiskLevel.REVIEW, scanner.scan("http://example.test/login").riskLevel)
    }
}
