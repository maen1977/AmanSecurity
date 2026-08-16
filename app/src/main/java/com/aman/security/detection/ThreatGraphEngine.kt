package com.aman.security.detection

/**
 * One-hop, reviewed relationship corroboration. Graph links never create a
 * confirmed verdict on their own; they only strengthen an already observed
 * non-test finding. This bounds false-positive propagation.
 *
 * 5.0.0 — Campaign clustering: when the same related indicator is corroborated
 * by at least two links, the convergence itself is promoted to a HIGH-level
 * cluster finding. Only findings of a single corroborated family are clustered,
 * so mixed families never merge into a fake consensus.
 */
object ThreatGraphEngine {
    fun correlate(findings: Collection<DetectionFinding>, links: List<ThreatGraphLink>): List<DetectionFinding> {
        if (findings.isEmpty() || links.isEmpty()) return emptyList()
        val seeds = findings.filter {
            it.family != ThreatFamily.UNKNOWN && it.family != ThreatFamily.TEST && it.score >= 10
        }
        if (seeds.isEmpty()) return emptyList()
        val byRef = seeds.flatMap { seed ->
            listOfNotNull(seed.reference, seed.id).distinct().map { it to seed }
        }.toMap()
        val baseCorrelations = links.mapNotNull { link ->
            val seed = byRef[link.fromId] ?: byRef[link.toId] ?: return@mapNotNull null
            val related = if (byRef.containsKey(link.fromId)) link.toId else link.fromId
            val confidence = when {
                seed.confidence.rank >= FindingConfidence.HIGH.rank && link.confidence.rank >= FindingConfidence.HIGH.rank -> FindingConfidence.HIGH
                seed.confidence.rank >= FindingConfidence.MEDIUM.rank && link.confidence.rank >= FindingConfidence.MEDIUM.rank -> FindingConfidence.MEDIUM
                else -> FindingConfidence.LOW
            }
            DetectionFinding(
                id = "GRAPH_${link.relation}_${related}",
                source = DetectionSource.THREAT_GRAPH,
                score = link.weight.coerceIn(1, 24),
                confidence = confidence,
                family = seed.family,
                reference = related
            )
        }.distinctBy { "${it.id}:${it.reference}" }

        // Campaign cluster: when the same related indicator is corroborated by
        // at least two links, the convergence itself is promoted to a HIGH-level
        // cluster finding. Only findings of a single corroborated family are
        // clustered, so mixed families never merge into a fake consensus.
        val clusters = baseCorrelations
            .groupBy { it.reference }
            .filter { (_, group) -> group.size >= 2 && group.map { it.family }.distinct().size == 1 }
            .map { (related, group) ->
                DetectionFinding(
                    id = "GRAPH_CLUSTER_${related}",
                    source = DetectionSource.THREAT_GRAPH,
                    score = 24,
                    confidence = FindingConfidence.HIGH,
                    family = group.first().family,
                    reference = related
                )
            }
        return baseCorrelations + clusters
    }
}
