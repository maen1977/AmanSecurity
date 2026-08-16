package com.aman.security.scanner

import com.aman.security.detection.DetectionFinding
import com.aman.security.detection.DetectionSource
import com.aman.security.detection.DetectionVerdictLevel
import com.aman.security.detection.FindingConfidence
import com.aman.security.detection.MultiEngineVerdict
import com.aman.security.detection.ThreatFamily
import org.junit.Assert.assertEquals
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
    fun keepsAllDistinctFindingsAndRemovesDuplicateComponentFindings() {
        val duplicate = DetectionFinding(
            id = "DUPLICATE_RULE",
            source = DetectionSource.SIGNATURE_RULE,
            score = 20,
            confidence = FindingConfidence.MEDIUM,
            family = ThreatFamily.RISKWARE,
            reference = "same-reference"
        )
        val unique = duplicate.copy(id = "UNIQUE_RULE", reference = "unique-reference")
        val verdict = MultiEngineVerdict(
            score = 20,
            level = DetectionVerdictLevel.REVIEW,
            family = ThreatFamily.RISKWARE,
            confidence = FindingConfidence.MEDIUM,
            findings = listOf(duplicate, unique),
            engineCount = 1
        )
        val analyses = listOf(
            ApkStaticAnalysis(ApkAnalysisState.VALID, advancedVerdict = verdict),
            ApkStaticAnalysis(ApkAnalysisState.VALID, advancedVerdict = verdict)
        )

        val merged = ApkComponentAnalysisPolicy.mergeFindings(analyses)

        assertEquals(2, merged.size)
        assertTrue(merged.any { it.id == "DUPLICATE_RULE" })
        assertTrue(merged.any { it.id == "UNIQUE_RULE" })
    }
}
