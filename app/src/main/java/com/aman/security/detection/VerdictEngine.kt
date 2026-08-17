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

        // A reviewed SAFE file/signer may suppress weak generic heuristics, but it must never
        // hide exact malicious reputation, known hashes, strong network IOCs or high-confidence
        // zero-day chains. This avoids both false positives and dangerous global allowlisting.
        val effective = if (allowlisted) {
            normalized.filterNot { finding ->
                finding.confidence.rank <= FindingConfidence.MEDIUM.rank &&
                    finding.source in setOf(
                        DetectionSource.MANIFEST,
                        DetectionSource.STATIC_BEHAVIOR,
                        DetectionSource.LOCAL_MODEL,
                        DetectionSource.IMPERSONATION,
                        DetectionSource.PACKER
                    )
            }
        } else normalized

        // Only malware-specific evidence can confirm a threat. A local model,
        // manifest permissions, static heuristics, packer signals, or graph
        // correlations may request review, but none can independently prove
        // that a legitimate installed app is malware.
        val confirmed = effective
            .filter(::isHardConfirmation)
            .maxByOrNull { it.score }
        val test = effective.firstOrNull { it.family == ThreatFamily.TEST }

        if (confirmed != null) {
            return MultiEngineVerdict(
                score = 100,
                level = DetectionVerdictLevel.KNOWN_THREAT,
                family = confirmed.family.takeUnless { it == ThreatFamily.UNKNOWN } ?: ThreatFamily.MALWARE,
                confidence = FindingConfidence.CONFIRMED,
                findings = normalized,
                engineCount = effective.map { it.source }.distinct().size,
                confirmedReference = confirmed.reference ?: confirmed.id,
                allowlisted = allowlisted
            )
        }

        if (test != null && effective.none { it.family != ThreatFamily.TEST && it.score >= 20 }) {
            return MultiEngineVerdict(
                score = 0,
                level = DetectionVerdictLevel.TEST,
                family = ThreatFamily.TEST,
                confidence = FindingConfidence.CONFIRMED,
                findings = normalized,
                engineCount = effective.map { it.source }.distinct().size,
                confirmedReference = test.reference ?: test.id,
                allowlisted = allowlisted
            )
        }

        val sources = effective.map { it.source }.distinct().size
        val domains = effective.map { evidenceDomain(it.source) }.distinct().size
        var score = effective.sumOf { finding ->
            val confidenceFactor = when (finding.confidence) {
                FindingConfidence.UNKNOWN -> 0.0
                FindingConfidence.LOW -> 0.45
                FindingConfidence.MEDIUM -> 0.75
                FindingConfidence.HIGH -> 1.0
                FindingConfidence.CONFIRMED -> 1.0
                FindingConfidence.CRITICAL -> 1.15
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
        val familyDomainCounts = effective
            .filter { it.family != ThreatFamily.UNKNOWN && it.family != ThreatFamily.TEST && it.confidence.rank >= FindingConfidence.MEDIUM.rank }
            .groupBy { it.family }
            .mapValues { (_, values) -> values.map { evidenceDomain(it.source) }.distinct().size }
        if ((familyDomainCounts.values.maxOrNull() ?: 0) >= 3) score += 4

        // Correlated heuristics from a single evidence domain must never become a HIGH malware
        // verdict just by stacking. This is the main false-positive guard for feature-rich benign
        // apps. Known threats were already handled above; heuristic HIGH requires corroboration
        // from at least two genuinely different evidence domains.
        val highestConfidence = effective.maxByOrNull { it.confidence.rank }?.confidence ?: FindingConfidence.LOW
        if (highestConfidence == FindingConfidence.LOW) score = score.coerceAtMost(34)
        if (domains < 2) score = score.coerceAtMost(49)

        // Permission/capability-derived static behavior and a local statistical model are review
        // hints, not malware evidence on their own. Without at least one malware-specific source,
        // keep the antivirus verdict LOW and surface permissions in Privacy Control instead.
        val hasMalwareSpecificEvidence = effective.any { finding ->
            finding.source in setOf(
                DetectionSource.FILE_HASH,
                DetectionSource.SIGNER_IDENTITY,
                DetectionSource.PACKAGE_IDENTITY,
                DetectionSource.SIGNATURE_RULE,
                DetectionSource.DEX,
                DetectionSource.ZERO_DAY_HEURISTIC,
                DetectionSource.NETWORK,
                DetectionSource.REPUTATION,
                DetectionSource.CLOUD_REPUTATION,
                DetectionSource.IMPERSONATION,
                DetectionSource.THREAT_GRAPH
            )
        }
        if (!hasMalwareSpecificEvidence) score = score.coerceAtMost(19)

        score = score.coerceIn(0, 99)

        val highConfidenceCount = effective.count {
            it.confidence.rank >= FindingConfidence.HIGH.rank &&
                it.family != ThreatFamily.TEST
        }
        val level = when {
            score >= 80 && domains >= 3 && highConfidenceCount >= 2 -> DetectionVerdictLevel.VERY_HIGH
            score >= 55 && domains >= 2 && highConfidenceCount >= 1 -> DetectionVerdictLevel.HIGH
            score >= 20 -> DetectionVerdictLevel.REVIEW
            else -> DetectionVerdictLevel.LOW
        }
        val family = effective
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

    private fun isHardConfirmation(finding: DetectionFinding): Boolean =
        finding.confidence == FindingConfidence.CONFIRMED &&
            finding.family != ThreatFamily.TEST &&
            finding.source in setOf(
                DetectionSource.FILE_HASH,
                DetectionSource.SIGNER_IDENTITY,
                DetectionSource.PACKAGE_IDENTITY,
                DetectionSource.SIGNATURE_RULE,
                DetectionSource.DEX,
                DetectionSource.NETWORK,
                DetectionSource.REPUTATION,
                DetectionSource.CLOUD_REPUTATION
            )

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
