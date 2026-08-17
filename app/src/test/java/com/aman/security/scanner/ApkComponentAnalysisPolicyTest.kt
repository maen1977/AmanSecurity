package com.aman.security.scanner

import com.aman.security.detection.DetectionFinding
import com.aman.security.detection.DetectionSource
import com.aman.security.detection.DetectionVerdictLevel
import com.aman.security.detection.FindingConfidence
import com.aman.security.detection.MultiEngineVerdict
import com.aman.security.detection.ThreatFamily
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ApkComponentAnalysisPolicyTest {
    @Test
    fun boundsDeepAnalysisToSixComponents() {
        val components = (0 until 9).map { index -> File("component-$index.apk") to "hash-$index" }

        val selected = ApkComponentAnalysisPolicy.selectForDeepAnalysis(components)

        assertEquals(6, selected.size)
        assertEquals("component-0.apk", selected.first().first.name)
        assertEquals("component-5.apk", selected.last().first.name)
    }

    @Test
    fun keepsDistinctHardConfirmationsAndRemovesDuplicates() {
        val duplicate = DetectionFinding(
            id = "DUPLICATE_HASH",
            source = DetectionSource.FILE_HASH,
            score = 95,
            confidence = FindingConfidence.CONFIRMED,
            family = ThreatFamily.MALWARE,
            reference = "same-reference"
        )
        val unique = duplicate.copy(id = "UNIQUE_SIGNER", source = DetectionSource.SIGNER_IDENTITY, reference = "unique-reference")
        val verdict = MultiEngineVerdict(
            score = 95,
            level = DetectionVerdictLevel.KNOWN_THREAT,
            family = ThreatFamily.MALWARE,
            confidence = FindingConfidence.CONFIRMED,
            findings = listOf(duplicate, unique),
            engineCount = 1
        )
        val analyses = listOf(
            ApkStaticAnalysis(ApkAnalysisState.VALID, advancedVerdict = verdict),
            ApkStaticAnalysis(ApkAnalysisState.VALID, advancedVerdict = verdict)
        )

        val merged = ApkComponentAnalysisPolicy.mergeFindings(analyses)

        assertEquals(2, merged.size)
        assertTrue(merged.any { it.id == "DUPLICATE_HASH" })
        assertTrue(merged.any { it.id == "UNIQUE_SIGNER" })
    }

    @Test
    fun dropsGenericDeepHeuristicsFromInstalledAppVerdict() {
        val genericDex = DetectionFinding(
            id = "GENERIC_DEX_BEHAVIOR",
            source = DetectionSource.DEX,
            score = 99,
            confidence = FindingConfidence.HIGH,
            family = ThreatFamily.RISKWARE,
            reference = "generic-dex"
        )
        val genericZeroDay = genericDex.copy(
            id = "GENERIC_ZERO_DAY",
            source = DetectionSource.ZERO_DAY_HEURISTIC,
            reference = "generic-zero-day"
        )
        val genericGraph = genericDex.copy(
            id = "GENERIC_GRAPH",
            source = DetectionSource.THREAT_GRAPH,
            reference = "generic-graph"
        )
        val verdict = MultiEngineVerdict(
            score = 99,
            level = DetectionVerdictLevel.HIGH,
            family = ThreatFamily.RISKWARE,
            confidence = FindingConfidence.HIGH,
            findings = listOf(genericDex, genericZeroDay, genericGraph),
            engineCount = 3
        )

        val merged = ApkComponentAnalysisPolicy.mergeFindings(
            listOf(ApkStaticAnalysis(ApkAnalysisState.VALID, advancedVerdict = verdict))
        )

        assertFalse(merged.any { it.id == "GENERIC_DEX_BEHAVIOR" })
        assertFalse(merged.any { it.id == "GENERIC_ZERO_DAY" })
        assertFalse(merged.any { it.id == "GENERIC_GRAPH" })
        assertTrue(merged.isEmpty())
    }
}
