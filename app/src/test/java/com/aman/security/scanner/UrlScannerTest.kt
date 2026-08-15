package com.aman.security.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlScannerTest {
    @Test
    fun cleanLookingHttpsLinkStaysLowWithoutClaimingSafety() {
        val result = scanner().scan("https://example.com/docs")
        assertEquals(UrlRiskLevel.LOW, result.riskLevel)
        assertEquals("https://example.com/docs", result.normalizedUrl)
        assertEquals("example.com", result.host)
        assertTrue(result.riskScore < 20)
    }

    @Test
    fun missingSchemeDefaultsToHttpsForScanning() {
        val result = scanner().scan("example.com/account")
        assertEquals("https://example.com/account", result.normalizedUrl)
        assertEquals(UrlRiskLevel.LOW, result.riskLevel)
    }

    @Test
    fun unsupportedSchemeIsRejected() {
        val result = scanner().scan("javascript:alert(1)")
        assertEquals(UrlRiskLevel.INVALID, result.riskLevel)
        assertEquals(null, result.normalizedUrl)
    }

    @Test
    fun combinedDeceptionSignalsReachHighRisk() {
        val result = scanner().scan("http://name@192.168.0.1:8080/verify-account")
        assertEquals(UrlRiskLevel.HIGH, result.riskLevel)
        assertTrue(result.signals.contains(UrlRiskSignal.USER_INFO))
        assertTrue(result.signals.contains(UrlRiskSignal.IP_ADDRESS_HOST))
        assertTrue(result.signals.contains(UrlRiskSignal.NON_STANDARD_PORT))
        assertTrue(result.riskScore >= 55)
    }

    @Test
    fun knownShortenerHidesDestinationAndRequiresReview() {
        val result = scanner().scan("https://bit.ly/account-verify")
        assertEquals(UrlRiskLevel.REVIEW, result.riskLevel)
        assertTrue(result.signals.contains(UrlRiskSignal.SHORTENER_HOST))
        assertTrue(result.riskScore >= 20)
    }

    @Test
    fun singleHttpSignalDoesNotBecomePhishingVerdict() {
        val result = scanner().scan("http://example.com/")
        assertEquals(UrlRiskLevel.LOW, result.riskLevel)
        assertTrue(result.signals.contains(UrlRiskSignal.PLAIN_HTTP))
        assertTrue(result.riskScore < 20)
    }

    @Test
    fun confirmedHostMatchOverridesHeuristicScore() {
        val hostHash = UrlScanner.sha256("example.com")
        val scanner = UrlScanner { kind, hash ->
            if (kind == UrlIndicatorKind.HOST && hash == hostHash) {
                UrlThreatIndicator(kind, hash, "URL000100", UrlThreatClassification.PHISHING)
            } else null
        }
        val result = scanner.scan("https://example.com/")
        assertEquals(UrlRiskLevel.KNOWN_PHISHING, result.riskLevel)
        assertEquals(100, result.riskScore)
        assertEquals("URL000100", result.threatReference)
    }

    @Test
    fun communityFeedMatchRequiresReviewInsteadOfHardBlock() {
        val hostHash = UrlScanner.sha256("community.example")
        val scanner = UrlScanner { kind, hash ->
            if (kind == UrlIndicatorKind.HOST && hash == hostHash) {
                UrlThreatIndicator(kind, hash, "COMMUNITY", UrlThreatClassification.SUSPICIOUS_SOURCE)
            } else null
        }
        val result = scanner.scan("https://community.example/login")
        assertEquals(UrlRiskLevel.REVIEW, result.riskLevel)
        assertEquals(35, result.riskScore)
        assertTrue(UrlRiskSignal.COMMUNITY_THREAT_FEED in result.signals)
    }

    @Test
    fun querySpecificLinkCanMatchAQuerylessLiveFeedIndicator() {
        val canonical = "https://shared.example/account/verify"
        val urlHash = UrlScanner.sha256(canonical)
        val scanner = UrlScanner { kind, hash ->
            if (kind == UrlIndicatorKind.URL && hash == urlHash) {
                UrlThreatIndicator(kind, hash, "LIVE_FEED_URL", UrlThreatClassification.PHISHING)
            } else null
        }
        val result = scanner.scan("https://shared.example/account/verify?session=unique-user-token")
        assertEquals(UrlRiskLevel.KNOWN_PHISHING, result.riskLevel)
        assertEquals(UrlIndicatorKind.URL, result.matchedKind)
        assertEquals("LIVE_FEED_URL", result.threatReference)
    }

    @Test
    fun bundledReservedTestHashesMatchNormalizerContract() {
        val host = UrlNormalizer.normalize("phishing.test") ?: error("normalization failed")
        val url = UrlNormalizer.normalize("https://malware.test/download") ?: error("normalization failed")
        assertEquals(
            "8c0da6076b802d89d0b34ae7c15dde3d6e410e5a91aa00e9ebb535dc61dca1d0",
            UrlScanner.sha256(host.host)
        )
        assertEquals(
            "0d51ee2fcbc128a194d7b2db53c668fde104df6766a5dac008a4588958ccac35",
            UrlScanner.sha256(url.url)
        )
    }

    @Test
    fun officialAmtsoAndroidPhishingPageIsRecognizedAsHarmlessTest() {
        val result = scanner().scan(OfficialWebTestIndicators.AMTSO_ANDROID_PHISHING_URL)
        assertEquals(UrlRiskLevel.TEST_SIGNATURE, result.riskLevel)
        assertEquals(0, result.riskScore)
        assertEquals(OfficialWebTestIndicators.AMTSO_ANDROID_PHISHING_REFERENCE, result.threatReference)
    }

    @Test
    fun normalAmtsoPagesAreNotPermanentlyBlockedAsTests() {
        val result = scanner().scan("https://www.amtso.org/security-features-check/")
        assertFalse(result.riskLevel == UrlRiskLevel.TEST_SIGNATURE)
    }

    @Test
    fun reservedTestIndicatorRemainsTestOnly() {
        val hostHash = UrlScanner.sha256("phishing.test")
        val scanner = UrlScanner { kind, hash ->
            if (kind == UrlIndicatorKind.HOST && hash == hostHash) {
                UrlThreatIndicator(kind, hash, "URLTEST0001", UrlThreatClassification.TEST_SIGNATURE)
            } else null
        }
        val result = scanner.scan("https://phishing.test/")
        assertEquals(UrlRiskLevel.TEST_SIGNATURE, result.riskLevel)
        assertEquals(0, result.riskScore)
        assertFalse(result.threatReference.isNullOrBlank())
    }

    private fun scanner() = UrlScanner { _, _ -> null }
}
