package com.aman.security.detection

/**
 * One-hop, reviewed relationship corroboration. Graph links never create a
 * confirmed verdict on their own; they only strengthen an already observed
 * non-test finding. This bounds false-positive propagation.
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
        return links.mapNotNull { link ->
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
    }
}
