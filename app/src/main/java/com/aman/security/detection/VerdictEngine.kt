package com.aman.security.detection

object VerdictEngine {
    fun evaluate(
        findings: Collection<DetectionFinding>,
        allowlisted: Boolean = false
    ): MultiEngineVerdict {
        val normalized = findings
            .filter { it.score >= 0 }
            .distinctBy { "${it.source}:${it.id}:${it.reference.orEmpty()}" }

        val confirmed = normalized
            .filter { it.confidence == FindingConfidence.CONFIRMED && it.family != ThreatFamily.TEST }
            .maxByOrNull { it.score }
        val test = normalized.firstOrNull { it.family == ThreatFamily.TEST }

        if (confirmed != null) {
            return MultiEngineVerdict(
                score = 100,
                level = DetectionVerdictLevel.KNOWN_THREAT,
                family = confirmed.family.takeUnless { it == ThreatFamily.UNKNOWN } ?: ThreatFamily.MALWARE,
                confidence = FindingConfidence.CONFIRMED,
                findings = normalized,
                engineCount = normalized.map { it.source }.distinct().size,
                confirmedReference = confirmed.reference ?: confirmed.id,
                allowlisted = allowlisted
            )
        }

        if (test != null && normalized.none { it.family != ThreatFamily.TEST && it.score >= 20 }) {
            return MultiEngineVerdict(
                score = 0,
                level = DetectionVerdictLevel.TEST,
                family = ThreatFamily.TEST,
                confidence = FindingConfidence.CONFIRMED,
                findings = normalized,
                engineCount = normalized.map { it.source }.distinct().size,
                confirmedReference = test.reference ?: test.id,
                allowlisted = allowlisted
            )
        }

        val sources = normalized.map { it.source }.distinct().size
        var score = normalized.sumOf { finding ->
            val confidenceFactor = when (finding.confidence) {
                FindingConfidence.LOW -> 0.45
                FindingConfidence.MEDIUM -> 0.75
                FindingConfidence.HIGH -> 1.0
                FindingConfidence.CONFIRMED -> 1.0
            }
            (finding.score * confidenceFactor).toInt()
        }

        // Multiple independent engines agreeing is materially stronger than one heuristic.
        score += when {
            sources >= 5 -> 18
            sources >= 4 -> 12
            sources >= 3 -> 8
            sources >= 2 -> 4
            else -> 0
        }

        // Low-confidence heuristics alone cannot escalate to a high verdict.
        val highestConfidence = normalized.maxByOrNull { it.confidence.rank }?.confidence ?: FindingConfidence.LOW
        if (highestConfidence == FindingConfidence.LOW) score = score.coerceAtMost(34)
        if (highestConfidence == FindingConfidence.MEDIUM && sources < 2) score = score.coerceAtMost(49)

        if (allowlisted) score = score.coerceAtMost(19)
        score = score.coerceIn(0, 99)

        val level = when {
            score >= 80 -> DetectionVerdictLevel.VERY_HIGH
            score >= 55 -> DetectionVerdictLevel.HIGH
            score >= 20 -> DetectionVerdictLevel.REVIEW
            else -> DetectionVerdictLevel.LOW
        }
        val family = normalized
            .filter { it.family != ThreatFamily.UNKNOWN && it.family != ThreatFamily.TEST }
            .groupBy { it.family }
            .maxByOrNull { (_, familyFindings) -> familyFindings.sumOf { it.score * it.confidence.rank } }
            ?.key ?: ThreatFamily.UNKNOWN

        return MultiEngineVerdict(
            score = score,
            level = level,
            family = family,
            confidence = highestConfidence,
            findings = normalized,
            engineCount = sources,
            allowlisted = allowlisted
        )
    }
}
