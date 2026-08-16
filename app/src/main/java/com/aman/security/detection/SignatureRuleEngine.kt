package com.aman.security.detection

/**
 * Marker-based rule matcher with false-positive guards.
 *
 * 5.0.0 — NOT-markers: if a trusted marker (for example a Google- or bank-
 * platform identity marker) is present, the rule is suppressed entirely,
 * because the surrounding markers belong to a legitimate application.
 * Multi-match boost: when the observation covers strictly more than half of
 * the rule's markers, the finding's score is strengthened toward the rule's
 * weight ceiling so that well-corroborated rules are treated decisively.
 */
object SignatureRuleEngine {
    fun match(markers: Set<String>, rules: List<DetectionRule>): List<DetectionFinding> {
        if (markers.isEmpty() || rules.isEmpty()) return emptyList()
        return rules.mapNotNull { rule ->
            val allMatched = rule.allMarkers.all(markers::contains)
            val anyMatched = rule.anyMarkers.isEmpty() || rule.anyMarkers.any(markers::contains)
            if (!allMatched || !anyMatched) return@mapNotNull null
            // NOT-markers are suppression markers: a single trusted marker vetoes the rule.
            val vetoed = rule.notMarkers.isNotEmpty() && rule.notMarkers.any(markers::contains)
            if (vetoed) return@mapNotNull null
            val covered = rule.allMarkers.count(markers::contains) + rule.anyMarkers.count(markers::contains)
            val total = rule.allMarkers.size + rule.anyMarkers.size
            val boosted = total > 1 && covered * 2 > total
            DetectionFinding(
                id = rule.id,
                source = DetectionSource.SIGNATURE_RULE,
                score = (if (boosted) (rule.weight * 1.25).toInt().coerceAtMost(100) else rule.weight).coerceIn(0, 100),
                confidence = rule.confidence,
                family = rule.family,
                reference = rule.id
            )
        }
    }
}
