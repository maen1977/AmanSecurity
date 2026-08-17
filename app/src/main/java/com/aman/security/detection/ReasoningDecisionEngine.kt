package com.aman.security.detection

/**
 * On-device reasoning layer — the "thinking AI" of Maen Shield.
 *
 * Instead of relying on a single engine, this fuses evidence from every
 * detection source (signatures, behavior, zero-day, local model, threat
 * graph, graph correlations) and produces a verdict with an explicit
 * decision chain: a human-readable explanation of *why* the verdict was
 * reached. Everything runs locally — no cloud, no extra dependencies.
 *
 * 6.0.0 — ReasoningDecisionEngine
 */
object ReasoningDecisionEngine {

    data class Evidence(
        val source: DetectionSource,
        val score: Int,
        val confidence: FindingConfidence,
        val family: ThreatFamily,
        val weight: Double
    )

    data class Reason(
        val source: DetectionSource,
        val severity: FindingConfidence,
        val reasonKey: String
    )

    data class ReasoningVerdict(
        val score: Int,
        val level: DetectionVerdictLevel,
        val family: ThreatFamily,
        val confidence: FindingConfidence,
        val reasons: List<Reason>,
        val reasoningChain: List<String>,
        val explanationKey: String
    )

    private const val HIGH_SCORE = 30
    private const val VERIFIED_HIGH = 60
    private const val CONFIRMED = 80
    private const val HIGH_LEVEL = 100
    private const val VERY_HIGH_LEVEL = 130

    /** Fuse multi-engine findings into a reasoned verdict with an explanation. */
    fun decide(findings: List<DetectionFinding>, confirmedReference: Boolean = false): ReasoningVerdict {
        if (findings.isEmpty()) {
            return ReasoningVerdict(
                0, DetectionVerdictLevel.LOW, ThreatFamily.UNKNOWN,
                FindingConfidence.LOW, emptyList(), emptyList(), "decision_safe"
            )
        }

        val evidence = findings
            .map(::normalizeFinding)
            .map { f -> Evidence(f.source, f.score, f.confidence, f.family, confidenceWeight(f.confidence)) }
        val fusedScore = evidence.sumOf { (it.score.toDouble() * it.weight).toInt() }
        val sources = evidence.map { it.source }.distinct()
        val confirmed = evidence.any(::isHardConfirmation)
        val verified = evidence.count { it.confidence == FindingConfidence.HIGH } >= 2
        val highestConfidence = evidence.maxByOrNull { it.confidence.rank }!!.confidence
        val dominantFamily = evidence.maxByOrNull { it.score * it.weight }!!.family
        val maxFused = fusedScore.coerceAtMost(VERY_HIGH_LEVEL)

        val (level, conf) = when {
            maxFused >= CONFIRMED && confirmed -> DetectionVerdictLevel.KNOWN_THREAT to FindingConfidence.CONFIRMED
            maxFused >= VERY_HIGH_LEVEL -> DetectionVerdictLevel.VERY_HIGH to highestConfidence
            maxFused >= HIGH_LEVEL || verified -> DetectionVerdictLevel.HIGH to highestConfidence
            maxFused >= REVIEW_LEVEL -> DetectionVerdictLevel.REVIEW to highestConfidence
            else -> DetectionVerdictLevel.LOW to FindingConfidence.LOW
        }

        val reasons = evidence.map { Reason(it.source, it.confidence, reasonKeyFor(it)) }
        val chain = buildChain(evidence, confirmedReference, confirmed, verified)
        val explanation = explanationKey(dominantFamily, level, chain.size)

        return ReasoningVerdict(maxFused, level, dominantFamily, conf, reasons, chain, explanation)
    }

    private fun normalizeFinding(finding: DetectionFinding): DetectionFinding =
        if (finding.confidence == FindingConfidence.CONFIRMED && !isHardConfirmation(finding)) {
            finding.copy(
                id = "${finding.id}_REVIEW",
                score = minOf(finding.score, 10),
                confidence = FindingConfidence.MEDIUM,
                family = ThreatFamily.RISKWARE,
                reference = finding.reference ?: "LOCAL_REVIEW"
            )
        } else finding

    private fun isHardConfirmation(finding: DetectionFinding): Boolean =
        finding.confidence == FindingConfidence.CONFIRMED &&
            finding.family != ThreatFamily.TEST &&
            finding.source in HARD_CONFIRMED_SOURCES

    private fun isHardConfirmation(evidence: Evidence): Boolean =
        evidence.confidence == FindingConfidence.CONFIRMED &&
            evidence.family != ThreatFamily.TEST &&
            evidence.source in HARD_CONFIRMED_SOURCES

    private val HARD_CONFIRMED_SOURCES = setOf(
        DetectionSource.FILE_HASH,
        DetectionSource.SIGNER_IDENTITY,
        DetectionSource.PACKAGE_IDENTITY,
        DetectionSource.SIGNATURE_RULE,
        DetectionSource.DEX,
        DetectionSource.NETWORK,
        DetectionSource.REPUTATION,
        DetectionSource.CLOUD_REPUTATION
    )

    private fun confidenceWeight(c: FindingConfidence): Double = when (c) {
        FindingConfidence.UNKNOWN -> 0.0
        FindingConfidence.LOW -> 0.7
        FindingConfidence.MEDIUM -> 1.0
        FindingConfidence.HIGH -> 1.3
        FindingConfidence.CONFIRMED -> 1.6
        FindingConfidence.CRITICAL -> 1.8
    }

    private fun reasonKeyFor(e: Evidence): String =
        "reason_${e.source.name.lowercase()}_${e.family.name.lowercase()}"

    private fun buildChain(
        evidence: List<Evidence>,
        confirmedReference: Boolean,
        confirmed: Boolean,
        verified: Boolean
    ): List<String> {
        val chain = mutableListOf<String>()
        if (confirmedReference) chain += "step_reference_blacklist"
        if (confirmed) chain += "step_confirmed_evidence"
        if (verified) chain += "step_dual_high_evidence"
        if (evidence.size > 1) chain += "step_cross_engine_corroboration"
        chain += "step_evidence_fusion"
        chain += "step_final_verdict"
        return chain
    }

    private fun explanationKey(family: ThreatFamily, level: DetectionVerdictLevel, steps: Int): String {
        val familyTag = familyKey(family)
        val levelTag = when (level) {
            DetectionVerdictLevel.KNOWN_THREAT -> "confirmed"
            DetectionVerdictLevel.VERY_HIGH -> "very_high"
            DetectionVerdictLevel.HIGH -> "high"
            DetectionVerdictLevel.REVIEW -> "review"
            else -> "safe"
        }
        return "explanation_${familyTag}_${levelTag}"
    }

    private fun familyKey(f: ThreatFamily): String = f.name.lowercase()

    private const val REVIEW_LEVEL = 20
}
