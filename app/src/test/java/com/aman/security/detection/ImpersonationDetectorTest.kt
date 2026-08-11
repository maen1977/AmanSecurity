package com.aman.security.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ImpersonationDetectorTest {
    private val profile = ProtectedBrandProfile(
        id = "WHATSAPP",
        officialPackage = "com.whatsapp",
        tokens = setOf("whatsapp")
    )

    @Test
    fun officialPackageIsNeverFlagged() {
        assertTrue(ImpersonationDetector.evaluate("com.whatsapp", listOf(profile)).isEmpty())
    }

    @Test
    fun unrelatedStorePackageUsingProtectedBrandLabelIsNotEnoughByItself() {
        val result = ImpersonationDetector.evaluate("com.example.update", "WhatsApp Security Update", listOf(profile))
        assertTrue(result.isEmpty())
    }

    @Test
    fun sideloadedBrandLabelCanBeReviewedAsImpersonation() {
        val result = ImpersonationDetector.evaluate(
            "com.example.update",
            "WhatsApp Security Update",
            listOf(profile),
            isSideloaded = true
        )
        assertTrue(result.isNotEmpty())
        assertEquals(FindingConfidence.MEDIUM, result.first().confidence)
    }

    @Test
    fun lookalikePackageIsOnlyLowConfidenceSignal() {
        val result = ImpersonationDetector.evaluate("com.whatsapq", listOf(profile))
        assertTrue(result.isNotEmpty())
        assertEquals(FindingConfidence.LOW, result.first().confidence)
        assertEquals(ThreatFamily.PHISHING, result.first().family)
    }
    @Test
    fun officialPackageWithReviewedSignerMismatchIsHighConfidenceSignal() {
        val reviewed = profile.copy(trustedSignerSha256 = setOf("a".repeat(64)))
        val result = ImpersonationDetector.evaluate(
            "com.whatsapp",
            "WhatsApp",
            listOf(reviewed),
            signerSha256 = "b".repeat(64)
        )
        assertEquals(1, result.size)
        assertEquals(FindingConfidence.HIGH, result.first().confidence)
        assertTrue(result.first().score >= 40)
    }

    @Test
    fun sideloadedLookalikeEscalatesOnlyToMediumConfidence() {
        val result = ImpersonationDetector.evaluate(
            "com.whatsapq",
            "WhatsApp",
            listOf(profile),
            isSideloaded = true
        )
        assertEquals(FindingConfidence.MEDIUM, result.first().confidence)
        assertTrue(result.first().score < 55)
    }


    @Test
    fun facebookSiblingPackageDoesNotTriggerBrandImpersonation() {
        val profiles = listOf(ProtectedBrandProfile("BRAND_FACEBOOK", "com.facebook.katana", setOf("facebook")))
        val findings = ImpersonationDetector.evaluate(
            packageName = "com.facebook.orca",
            appLabel = "Messenger",
            profiles = profiles,
            signerSha256 = null,
            isSideloaded = false
        )
        assertTrue(findings.isEmpty())
    }
}
