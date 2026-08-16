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
    fun hiddenUnicodeAndPhonePressureAreFlagged() {
        val result = scanner.scan("\u200BYour bank account \u202Aneeds urgent\u202C transfer of money, call +962 7 9999 1234")

        assertTrue(MessageRiskSignal.HIDDEN_UNICODE in result.signals)
        assertTrue(MessageRiskSignal.PHONE_NUMBER_PRESSURE in result.signals)
        assertTrue(MessageRiskSignal.URGENT_LANGUAGE in result.signals)
        assertTrue(result.riskLevel == MessageRiskLevel.REVIEW || result.riskLevel == MessageRiskLevel.HIGH)
    }

    @Test
    fun bankTransferUrgencyComboIsFlagged() {
        val result = scanner.scan("Urgent: your account transfer is suspended. Verify your password at https://example.com/x to restore access.")

        assertTrue(MessageRiskSignal.BANK_TRANSFER_URGENCY in result.signals)
        assertTrue(MessageRiskSignal.URGENT_LANGUAGE in result.signals)
        assertTrue(MessageRiskSignal.PAYMENT_REQUEST in result.signals)
        assertTrue(MessageRiskSignal.CREDENTIAL_REQUEST in result.signals)
        assertTrue(result.riskLevel == MessageRiskLevel.HIGH)
    }

    @Test
    fun threeStackedSignalsTriggersSmishingCombo() {
        val result = scanner.scan("\u200BUrgent message: your account is blocked. Call +962 7 9999 1234 to verify your identity and restore the wallet transfer. https://example.com/restore")

        assertTrue(MessageRiskSignal.SMISHING_COMBO in result.signals)
        assertTrue(result.riskLevel == MessageRiskLevel.HIGH)
    }

    @Test
    fun ordinaryPhoneMentionWithoutPressureStaysLow() {
        val result = scanner.scan("Call me at +962 7 1234 5678 when you are free, thanks.")

        assertEquals(MessageRiskLevel.LOW, result.riskLevel)
        assertTrue(MessageRiskSignal.PHONE_NUMBER_PRESSURE !in result.signals)
    }

    @Test
    fun sharedExtractorReturnsDistinctBoundedLinks() {
        val links = SharedUrlExtractor.allCandidates(
            "See https://example.com/a, then https://example.com/a and https://example.org/b."
        )

        assertEquals(listOf("https://example.com/a", "https://example.org/b"), links)
    }
}
