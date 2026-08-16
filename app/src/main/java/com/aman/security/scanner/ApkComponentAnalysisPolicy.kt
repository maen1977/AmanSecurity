package com.aman.security.scanner

import com.aman.security.detection.DetectionFinding
import java.io.File

/**
 * Lightweight policy for bounded deep analysis of installed APK components.
 *
 * Component hashes and reputation checks still cover every discovered APK. Deep
 * static inspection is bounded to protect older phones from unusually large
 * split sets, while the selected components' findings are deduplicated before
 * the final verdict is calculated.
 */
object ApkComponentAnalysisPolicy {
    const val MAX_DEEP_COMPONENT_ANALYSES = 6

    fun selectForDeepAnalysis(
        components: List<Pair<File, String>>
    ): List<Pair<File, String>> = components.take(MAX_DEEP_COMPONENT_ANALYSES)

    fun mergeFindings(analyses: List<ApkStaticAnalysis>): List<DetectionFinding> =
        analyses
            .flatMap { it.advancedVerdict?.findings.orEmpty() }
            .distinctBy { Triple(it.id, it.source, it.reference) }
}
