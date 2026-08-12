package com.aman.security.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DataExfiltrationPolicyTest {
    private val mib = 1024L * 1024L

    @Test
    fun largeUploadAloneIsNotDataTheft() {
        val result = DataExfiltrationPolicy.evaluate(
            DataExfiltrationInput(
                backgroundTxBytes = 300 * mib,
                foregroundTxBytes = 0,
                sideloaded = false,
                privilegedControlCount = 0,
                surveillanceSignalCount = 0,
                persistent = false,
                recentDnsHostCount = 30,
                systemApp = false
            )
        )
        assertEquals(DataExfiltrationLevel.CLEAR, result.level)
    }

    @Test
    fun corroboratedSideloadedControllerWithBackgroundUploadIsHigh() {
        val result = DataExfiltrationPolicy.evaluate(
            DataExfiltrationInput(
                backgroundTxBytes = 80 * mib,
                foregroundTxBytes = 2 * mib,
                sideloaded = true,
                privilegedControlCount = 1,
                surveillanceSignalCount = 2,
                persistent = true,
                recentDnsHostCount = 14,
                systemApp = false
            )
        )
        assertEquals(DataExfiltrationLevel.HIGH, result.level)
        assertTrue(result.score >= 75)
    }

    @Test
    fun moderateCorroboratedBackgroundUploadNeedsReview() {
        val result = DataExfiltrationPolicy.evaluate(
            DataExfiltrationInput(
                backgroundTxBytes = 24 * mib,
                foregroundTxBytes = 0,
                sideloaded = true,
                privilegedControlCount = 1,
                surveillanceSignalCount = 1,
                persistent = false,
                recentDnsHostCount = 3,
                systemApp = false
            )
        )
        assertEquals(DataExfiltrationLevel.REVIEW, result.level)
        assertTrue(result.score >= 40)
    }

    @Test
    fun systemAppIsNeverEscalatedByTrafficPolicyAlone() {
        val result = DataExfiltrationPolicy.evaluate(
            DataExfiltrationInput(
                backgroundTxBytes = 500 * mib,
                foregroundTxBytes = 0,
                sideloaded = true,
                privilegedControlCount = 3,
                surveillanceSignalCount = 5,
                persistent = true,
                recentDnsHostCount = 50,
                systemApp = true
            )
        )
        assertEquals(DataExfiltrationLevel.CLEAR, result.level)
    }
}
