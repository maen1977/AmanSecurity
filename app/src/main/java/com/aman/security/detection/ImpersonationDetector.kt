package com.aman.security.detection

object ImpersonationDetector {
    fun evaluate(packageName: String, profiles: List<ProtectedBrandProfile>): List<DetectionFinding> =
        evaluate(packageName, null, profiles)

    fun evaluate(
        packageName: String,
        appLabel: String?,
        profiles: List<ProtectedBrandProfile>,
        signerSha256: String? = null,
        isSideloaded: Boolean = false
    ): List<DetectionFinding> {
        val normalizedPackage = packageName.lowercase()
        val normalizedLabel = appLabel.orEmpty().lowercase()
        val normalizedSigner = signerSha256?.lowercase()
        return profiles.mapNotNull { profile ->
            val official = profile.officialPackage.lowercase()
            val hasReviewedSigners = profile.trustedSignerSha256.isNotEmpty()
            val signerMismatch = hasReviewedSigners && normalizedSigner != null &&
                normalizedSigner !in profile.trustedSignerSha256

            if (normalizedPackage == official) {
                if (!signerMismatch) return@mapNotNull null
                return@mapNotNull DetectionFinding(
                    id = "OFFICIAL_PACKAGE_SIGNER_MISMATCH_${profile.id}",
                    source = DetectionSource.IMPERSONATION,
                    score = 42,
                    confidence = FindingConfidence.HIGH,
                    family = ThreatFamily.PHISHING,
                    reference = profile.id
                )
            }

            val closePackage = editDistance(normalizedPackage, official) <= 3
            val packageTokenHit = profile.tokens.any { token -> normalizedPackage.contains(token.lowercase()) }
            val labelTokenHit = normalizedLabel.isNotBlank() && profile.tokens.any { token ->
                normalizedLabel.contains(token.lowercase())
            }
            if (!closePackage && !packageTokenHit && !labelTokenHit) return@mapNotNull null

            var score = when {
                closePackage -> 18
                labelTokenHit -> 14
                else -> 10
            }
            if (isSideloaded) score += 8
            if (signerMismatch) score += 14
            val confidence = if (signerMismatch || (isSideloaded && (closePackage || labelTokenHit))) {
                FindingConfidence.MEDIUM
            } else {
                FindingConfidence.LOW
            }
            DetectionFinding(
                id = "IMPERSONATION_${profile.id}",
                source = DetectionSource.IMPERSONATION,
                score = score.coerceAtMost(44),
                confidence = confidence,
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
