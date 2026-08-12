package com.aman.security.banking

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FinanceAppIdentityMatcherTest {
    @Test
    fun detectsCommonBankingIdentityWithoutAndroidCategory() {
        assertTrue(FinanceAppIdentityMatcher.matches("com.arabbank.mobile", "Arabi Mobile"))
        assertTrue(FinanceAppIdentityMatcher.matches("com.example.wallet", "My Wallet"))
        assertTrue(FinanceAppIdentityMatcher.matches("com.example.app", "البنك العربي"))
    }

    @Test
    fun doesNotTreatOrdinaryAppsAsFinanceApps() {
        assertFalse(FinanceAppIdentityMatcher.matches("com.whatsapp", "WhatsApp"))
        assertFalse(FinanceAppIdentityMatcher.matches("com.facebook.orca", "Messenger"))
        assertFalse(FinanceAppIdentityMatcher.matches("com.openai.chatgpt", "ChatGPT"))
    }
}
