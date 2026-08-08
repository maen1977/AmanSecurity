package com.aman.security.detection

object ImpersonationDetector {
    fun evaluate(packageName: String, profiles: List<ProtectedBrandProfile>): List<DetectionFinding> =
        evaluate(packageName, null, profiles)

    fun evaluate(
        packageName: String,
        appLabel: String?,
        profiles: List<ProtectedBrandProfile>
    ): List<DetectionFinding> {
        val normalizedPackage = packageName.lowercase()
        val normalizedLabel = appLabel.orEmpty().lowercase()
        return profiles.mapNotNull { profile ->
            val official = profile.officialPackage.lowercase()
            if (normalizedPackage == official) return@mapNotNull null
            val closePackage = editDistance(normalizedPackage, official) <= 3
            val packageTokenHit = profile.tokens.any { token -> normalizedPackage.contains(token.lowercase()) }
            val labelTokenHit = normalizedLabel.isNotBlank() && profile.tokens.any { token ->
                normalizedLabel.contains(token.lowercase())
            }
            if (!closePackage && !packageTokenHit && !labelTokenHit) return@mapNotNull null
            DetectionFinding(
                id = "IMPERSONATION_${profile.id}",
                source = DetectionSource.IMPERSONATION,
                score = when {
                    closePackage -> 18
                    labelTokenHit -> 14
                    else -> 10
                },
                confidence = FindingConfidence.LOW,
                family = ThreatFamily.PHISHING,
                reference = profile.id
            )
        }
    }

    private fun editDistance(a: String, b: String): Int {
        if (a == b) return 0
        if (a.isEmpty()) return b.length
        if (b.isEmpty()) return a.length
        var previous = IntArray(b.length + 1) { it }
        var current = IntArray(b.length + 1)
        for (i in a.indices) {
            current[0] = i + 1
            for (j in b.indices) {
                val cost = if (a[i] == b[j]) 0 else 1
                current[j + 1] = minOf(current[j] + 1, previous[j + 1] + 1, previous[j] + cost)
            }
            val tmp = previous
            previous = current
            current = tmp
        }
        return previous[b.length]
    }
}
