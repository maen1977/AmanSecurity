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
    ): List<DetectionFinding> = evaluate(
        packageName = packageName,
        appLabel = appLabel,
        profiles = profiles,
        signerSha256s = signerSha256?.let(::setOf).orEmpty(),
        isSideloaded = isSideloaded
    )

    fun evaluate(
        packageName: String,
        appLabel: String?,
        profiles: List<ProtectedBrandProfile>,
        signerSha256s: Set<String>,
        isSideloaded: Boolean = false
    ): List<DetectionFinding> {
        val normalizedPackage = packageName.lowercase()
        val normalizedLabel = appLabel.orEmpty().lowercase()
        val normalizedSigners = signerSha256s.map(String::lowercase).toSet()
        return profiles.mapNotNull { profile ->
            val official = profile.officialPackage.lowercase()
            val hasReviewedSigners = profile.trustedSignerSha256.isNotEmpty()
            val signerMismatch = hasReviewedSigners && normalizedSigners.isNotEmpty() &&
                normalizedSigners.none(profile.trustedSignerSha256::contains)

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
            val labelTokenHit = normalizedLabel.isNotBlank() && profile.tokens.any { token ->
                normalizedLabel.contains(token.lowercase())
            }

            // A package merely containing a brand token is not impersonation. Vendors commonly
            // publish multiple legitimate sibling packages (for example a main app and a messenger).
            // Require a typo-close package name, or a brand-like label on an explicitly sideloaded
            // package. Signer mismatch for the exact official package is handled above.
            if (!closePackage && !(labelTokenHit && isSideloaded)) return@mapNotNull null

            var score = when {
                closePackage -> 18
                else -> 14
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
