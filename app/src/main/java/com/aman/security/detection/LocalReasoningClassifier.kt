package com.aman.security.detection

/**
 * On-device reasoning classifier — the third pillar of the "thinking AI"
 * layer.
 *
 * A tiny pre-trained linear model (logistic regression with a small set
 * of hand-picked composite features) that reasons about the *shape* of an
 * app rather than individual features. It consumes a normalized reasoning
 * vector (0..1 per dimension) produced from the raw scan signals and
 * outputs a probability plus the top contributing dimensions — which the
 * UI then shows as an explanation.
 *
 * The weights are generated offline by tools/build_reasoning_weights.py
 * (trained on synthetic malicious/benign app profiles) and shipped inside
 * the cloud threat database so they stay in sync with the rest of the
 * ruleset. Memory footprint is a few kilobytes.
 *
 * 6.0.0 — LocalReasoningClassifier
 */
class LocalReasoningClassifier(private val weights: Map<String, Double>) {

    data class ReasoningResult(
        val probability: Double,
        val topContributors: List<Pair<String, Double>>,
        val finding: DetectionFinding?
    )

    fun reason(vector: Map<String, Double>): ReasoningResult {
        var z = weights["bias"] ?: -2.5
        val contributions = vector.mapValues { (key, v) ->
            val w = weights[key] ?: 0.0
            z += w * v.coerceIn(-1.0, 1.0)
            w * v.coerceIn(-1.0, 1.0)
        }
        val probability = 1.0 / (1.0 + kotlin.math.exp(-z.coerceIn(-12.0, 12.0)))
        val top = contributions.entries
            .sortedByDescending { it.value }
            .take(3)
            .filter { it.value > 0 }
            .map { it.key to it.value }

        val finding = when {
            probability >= 0.92 -> DetectionFinding(
                "REASONING_AI_CONFIRMED", DetectionSource.LOCAL_MODEL, 30,
                FindingConfidence.CONFIRMED, ThreatFamily.MALWARE
            )
            probability >= 0.80 -> DetectionFinding(
                "REASONING_AI_HIGH", DetectionSource.LOCAL_MODEL, 20,
                FindingConfidence.HIGH, ThreatFamily.MALWARE
            )
            probability >= 0.65 -> DetectionFinding(
                "REASONING_AI_REVIEW", DetectionSource.LOCAL_MODEL, 10,
                FindingConfidence.MEDIUM, ThreatFamily.RISKWARE
            )
            else -> null
        }
        return ReasoningResult(probability, top, finding)
    }
}
