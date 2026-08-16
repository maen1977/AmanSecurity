package com.aman.security.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MessageScannerTest {
    private val scanner = MessageScanner(UrlScanner { _, _ -> null })

    @Test
    fun urgentCredentialAndPaymentMessageNeedsReview() {
        val result = scanner.scan("Urgent: verify your bank account now at https://example.com/login")

        assertTrue(result.riskLevel == MessageRiskLevel.REVIEW || result.riskLevel == MessageRiskLevel.HIGH)
        assertTrue(MessageRiskSignal.URGENT_LANGUAGE in result.signals)
        assertTrue(MessageRiskSignal.CREDENTIAL_REQUEST in result.signals)
        assertTrue(MessageRiskSignal.PAYMENT_REQUEST in result.signals)
    }

    @Test
    fun shortenedLinkIsHighlightedEvenWithoutOtherTextSignals() {
        val result = scanner.scan("Open https://bit.ly/abc")

        assertTrue(MessageRiskSignal.SHORTENED_URL in result.signals)
        assertTrue(result.riskLevel == MessageRiskLevel.REVIEW || result.riskLevel == MessageRiskLevel.HIGH)
    }

    @Test
    fun remoteAccessRequestIsHighlighted() {
        val result = scanner.scan("Security support asks you to install AnyDesk and share your screen")

        assertTrue(MessageRiskSignal.REMOTE_ACCESS_REQUEST in result.signals)
        assertTrue(result.riskLevel == MessageRiskLevel.REVIEW || result.riskLevel == MessageRiskLevel.HIGH)
    }

    @Test
    fun apkInstallRequestWithLinkIsHighlighted() {
        val result = scanner.scan("Download this app and install the APK: https://example.com/app.apk")

        assertTrue(MessageRiskSignal.APP_INSTALL_REQUEST in result.signals)
        assertTrue(result.riskLevel == MessageRiskLevel.REVIEW || result.riskLevel == MessageRiskLevel.HIGH)
    }

    @Test
    fun ordinaryMessageRemainsLowRisk() {
        val result = scanner.scan("Your appointment is scheduled for Tuesday at 10:00.")

        assertEquals(MessageRiskLevel.LOW, result.riskLevel)
        assertTrue(result.signals.isEmpty())
    }

    @Test
    fun sharedExtractorReturnsDistinctBoundedLinks() {
        val links = SharedUrlExtractor.allCandidates(
            "See https://example.com/a, then https://example.com/a and https://example.org/b."
        )

        assertEquals(listOf("https://example.com/a", "https://example.org/b"), links)
    }
}
