package com.aman.security.scanner

import com.aman.security.detection.DetectionFinding
import com.aman.security.detection.VerdictEngine
import java.io.File

/**
 * Lightweight policy for bounded deep analysis of installed APK components.
 *
 * Component hashes and reputation checks still cover every discovered APK. Deep
 * static inspection is bounded to protect older phones from unusually large
 * split sets. For the installed-app antivirus verdict, however, generic static,
 * graph, and zero-day heuristics are review context only; only malware-specific
 * hard confirmations may be merged into the final installed-app finding set.
 */
object ApkComponentAnalysisPolicy {
    const val MAX_DEEP_COMPONENT_ANALYSES = 6

    fun selectForDeepAnalysis(
        components: List<Pair<File, String>>
    ): List<Pair<File, String>> = components.take(MAX_DEEP_COMPONENT_ANALYSES)

    fun isAntimalwareEvidence(finding: DetectionFinding): Boolean =
        VerdictEngine.isHardConfirmation(finding)

    fun mergeFindings(analyses: List<ApkStaticAnalysis>): List<DetectionFinding> =
        analyses
            .flatMap { it.advancedVerdict?.findings.orEmpty() }
            .filter(::isAntimalwareEvidence)
            .distinctBy { Triple(it.id, it.source, it.reference) }
}
