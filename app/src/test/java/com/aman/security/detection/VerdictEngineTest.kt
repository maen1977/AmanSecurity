package com.aman.security.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VerdictEngineTest {
    @Test
    fun confirmedMaliciousFindingOverridesHeuristics() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding(
                    id = "KNOWN_SIGNER",
                    source = DetectionSource.SIGNER_IDENTITY,
                    score = 90,
                    confidence = FindingConfidence.CONFIRMED,
                    family = ThreatFamily.TROJAN,
                    reference = "signer:deadbeef"
                )
            )
        )
        assertEquals(100, verdict.score)
        assertEquals(DetectionVerdictLevel.KNOWN_THREAT, verdict.level)
        assertEquals(ThreatFamily.TROJAN, verdict.family)
    }

    @Test
    fun oneLowConfidenceHeuristicCannotBecomeHighRisk() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding(
                    id = "OBFUSCATED",
                    source = DetectionSource.PACKER,
                    score = 90,
                    confidence = FindingConfidence.LOW,
                    family = ThreatFamily.RISKWARE
                )
            )
        )
        assertTrue(verdict.score <= 34)
        assertTrue(verdict.level == DetectionVerdictLevel.REVIEW || verdict.level == DetectionVerdictLevel.LOW)
    }

    @Test
    fun independentEnginesIncreaseConfidence() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                // Use genuinely independent evidence domains: static code, network, and impersonation.
                DetectionFinding("RULE", DetectionSource.SIGNATURE_RULE, 30, FindingConfidence.HIGH, ThreatFamily.SPYWARE),
                DetectionFinding("NETWORK", DetectionSource.NETWORK, 25, FindingConfidence.HIGH, ThreatFamily.SPYWARE),
                DetectionFinding("IMPERSONATION", DetectionSource.IMPERSONATION, 20, FindingConfidence.HIGH, ThreatFamily.SPYWARE)
            )
        )
        assertEquals(3, verdict.engineCount)
        assertTrue(verdict.score >= 80)
        assertEquals(ThreatFamily.SPYWARE, verdict.family)
    }

    @Test
    fun correlatedFileEncryptionHeuristicsStayReviewWithoutCorroboration() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding("RULE_RANSOMWARE", DetectionSource.SIGNATURE_RULE, 20, FindingConfidence.MEDIUM, ThreatFamily.RANSOMWARE),
                DetectionFinding("BEHAVIOR_RANSOMWARE", DetectionSource.STATIC_BEHAVIOR, 18, FindingConfidence.MEDIUM, ThreatFamily.RANSOMWARE)
            )
        )
        assertEquals(DetectionVerdictLevel.REVIEW, verdict.level)
        assertTrue(verdict.score < 55)
    }

    @Test
    fun exactAllowlistDoesNotRewriteConfirmedThreatAsClean() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding("KNOWN", DetectionSource.FILE_HASH, 100, FindingConfidence.CONFIRMED, ThreatFamily.MALWARE)
            ),
            allowlisted = true
        )
        assertEquals(DetectionVerdictLevel.KNOWN_THREAT, verdict.level)
        assertEquals(100, verdict.score)
        assertTrue(verdict.allowlisted)
    }

    @Test
    fun exactAllowlistDoesNotBlindStrongMalwareSpecificEvidence() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding("RULE", DetectionSource.SIGNATURE_RULE, 75, FindingConfidence.HIGH, ThreatFamily.MALWARE)
            ),
            allowlisted = true
        )
        // One static-code domain alone still cannot become HIGH, but SAFE reputation no longer
        // erases strong malware-specific evidence by globally forcing the score below review.
        assertTrue(verdict.score <= 49)
        assertEquals(DetectionVerdictLevel.REVIEW, verdict.level)
        assertTrue(verdict.allowlisted)
    }

    @Test
    fun correlatedStaticEnginesDoNotReceiveIndependentDomainBonus() {
        val a = VerdictEngine.evaluate(
            listOf(
                DetectionFinding("RULE", DetectionSource.SIGNATURE_RULE, 20, FindingConfidence.MEDIUM, ThreatFamily.DROPPER),
                DetectionFinding("ZERO", DetectionSource.ZERO_DAY_HEURISTIC, 20, FindingConfidence.MEDIUM, ThreatFamily.DROPPER)
            )
        )
        // Both findings come from the same static-code evidence domain, so no convergence bonus is added.
        assertEquals(30, a.score)
        assertEquals(DetectionVerdictLevel.REVIEW, a.level)
    }

    @Test
    fun confirmedLocalModelCannotBecomeKnownThreatByItself() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding(
                    "LOCAL_MODEL_96",
                    DetectionSource.LOCAL_MODEL,
                    100,
                    FindingConfidence.CONFIRMED,
                    ThreatFamily.MALWARE,
                    reference = "LOCAL_MODEL_96"
                ),
                DetectionFinding(
                    "PERMISSIONS",
                    DetectionSource.MANIFEST,
                    35,
                    FindingConfidence.HIGH,
                    ThreatFamily.RISKWARE
                )
            )
        )
        assertTrue(verdict.level != DetectionVerdictLevel.KNOWN_THREAT)
        assertTrue(verdict.score <= 19)
    }

    @Test
    fun commonOfficialAppPermissionProfilesStayReviewAcrossPackages() {
        val packages = listOf(
            "org.telegram.messenger",
            "com.truecaller",
            "com.facebook.katana",
            "com.google.android.apps.drive"
        )
        packages.forEach { packageName ->
            val verdict = VerdictEngine.evaluate(
                listOf(
                    DetectionFinding(
                        id = "LOCAL_MODEL_96",
                        source = DetectionSource.LOCAL_MODEL,
                        score = 100,
                        confidence = FindingConfidence.CONFIRMED,
                        family = ThreatFamily.MALWARE,
                        reference = "LOCAL_MODEL_96"
                    ),
                    DetectionFinding(
                        id = "INSTALLED_PERMISSION_CLUSTER",
                        source = DetectionSource.MANIFEST,
                        score = 26,
                        confidence = FindingConfidence.MEDIUM,
                        family = ThreatFamily.RISKWARE,
                        reference = packageName
                    )
                )
            )
            assertTrue("$packageName must not be a confirmed threat", verdict.level != DetectionVerdictLevel.KNOWN_THREAT)
            assertTrue("$packageName must remain below malware threshold", verdict.score <= 19)
        }
    }

    @Test
    fun exactReputationStillConfirmsWhenLocalModelAlsoFires() {
        val verdict = VerdictEngine.evaluate(
            listOf(
                DetectionFinding(
                    "LOCAL_MODEL_96",
                    DetectionSource.LOCAL_MODEL,
                    10,
                    FindingConfidence.MEDIUM,
                    ThreatFamily.RISKWARE
                ),
                DetectionFinding(
                    "KNOWN_HASH",
                    DetectionSource.FILE_HASH,
                    100,
                    FindingConfidence.CONFIRMED,
                    ThreatFamily.MALWARE,
                    reference = "HASH_BAD_1"
                )
            )
        )
        assertEquals(DetectionVerdictLevel.KNOWN_THREAT, verdict.level)
        assertEquals("HASH_BAD_1", verdict.confirmedReference)
    }
}
