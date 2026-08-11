package com.aman.security.detection

object VerdictEngine {
    private enum class EvidenceDomain {
        IDENTITY,
        STATIC_CODE,
        NETWORK,
        REPUTATION,
        IMPERSONATION,
        GRAPH,
        USER
    }

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
        val domains = normalized.map { evidenceDomain(it.source) }.distinct().size
        var score = normalized.sumOf { finding ->
            val confidenceFactor = when (finding.confidence) {
                FindingConfidence.LOW -> 0.45
                FindingConfidence.MEDIUM -> 0.75
                FindingConfidence.HIGH -> 1.0
                FindingConfidence.CONFIRMED -> 1.0
            }
            (finding.score * confidenceFactor).toInt()
        }

        // Only genuinely different evidence domains earn a convergence bonus. Multiple static
        // engines often derive from the same DEX/manifest evidence and must not double-count it.
        score += when {
            domains >= 5 -> 16
            domains >= 4 -> 10
            domains >= 3 -> 6
            domains >= 2 -> 3
            else -> 0
        }

        // Small consensus bonus when at least three independent evidence domains agree on a family.
        val familyDomainCounts = normalized
            .filter { it.family != ThreatFamily.UNKNOWN && it.family != ThreatFamily.TEST && it.confidence.rank >= FindingConfidence.MEDIUM.rank }
            .groupBy { it.family }
            .mapValues { (_, values) -> values.map { evidenceDomain(it.source) }.distinct().size }
        if ((familyDomainCounts.values.maxOrNull() ?: 0) >= 3) score += 4

        // Correlated heuristics from a single evidence domain must never become a HIGH malware
        // verdict just by stacking. This is the main false-positive guard for feature-rich benign
        // apps. Known threats were already handled above; heuristic HIGH requires corroboration
        // from at least two genuinely different evidence domains.
        val highestConfidence = normalized.maxByOrNull { it.confidence.rank }?.confidence ?: FindingConfidence.LOW
        if (highestConfidence == FindingConfidence.LOW) score = score.coerceAtMost(34)
        if (domains < 2) score = score.coerceAtMost(49)

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

    private fun evidenceDomain(source: DetectionSource): EvidenceDomain = when (source) {
        DetectionSource.FILE_HASH,
        DetectionSource.SIGNER_IDENTITY,
        DetectionSource.PACKAGE_IDENTITY -> EvidenceDomain.IDENTITY

        DetectionSource.SIGNATURE_RULE,
        DetectionSource.MANIFEST,
        DetectionSource.DEX,
        DetectionSource.PACKER,
        DetectionSource.STATIC_BEHAVIOR,
        DetectionSource.ZERO_DAY_HEURISTIC,
        DetectionSource.LOCAL_MODEL -> EvidenceDomain.STATIC_CODE

        DetectionSource.NETWORK -> EvidenceDomain.NETWORK
        DetectionSource.REPUTATION,
        DetectionSource.CLOUD_REPUTATION -> EvidenceDomain.REPUTATION
        DetectionSource.IMPERSONATION -> EvidenceDomain.IMPERSONATION
        DetectionSource.THREAT_GRAPH -> EvidenceDomain.GRAPH
        DetectionSource.USER_ALLOWLIST -> EvidenceDomain.USER
    }
}
