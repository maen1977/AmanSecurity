package com.aman.security.detection

object SignatureRuleEngine {
    fun match(markers: Set<String>, rules: List<DetectionRule>): List<DetectionFinding> {
        if (markers.isEmpty() || rules.isEmpty()) return emptyList()
        return rules.mapNotNull { rule ->
            val allMatched = rule.allMarkers.all(markers::contains)
            val anyMatched = rule.anyMarkers.isEmpty() || rule.anyMarkers.any(markers::contains)
            if (!allMatched || !anyMatched) return@mapNotNull null
            DetectionFinding(
                id = rule.id,
                source = DetectionSource.SIGNATURE_RULE,
                score = rule.weight.coerceIn(0, 100),
                confidence = rule.confidence,
                family = rule.family,
                reference = rule.id
            )
        }
    }
}
