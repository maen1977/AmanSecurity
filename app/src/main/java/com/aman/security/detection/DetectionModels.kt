package com.aman.security.detection

enum class ThreatFamily {
    UNKNOWN,
    MALWARE,
    TROJAN,
    SPYWARE,
    STALKERWARE,
    BANKER,
    RAT,
    DROPPER,
    RANSOMWARE,
    PHISHING,
    RISKWARE,
    ADWARE,
    SMISHER,
    OVERLAY_FRAUD,
    BANK_IMPERSONATOR,
    INSTALLER_FRAUD,
    KEYLOGGER,
    OTP_STEALER,
    SNIPPER,
    DATA_THIEF,
    FRAUD,
    SCAREWARE,
    PHISHER,
    CREDENTIAL_STEALER,
    TEST
}

enum class DetectionSource {
    FILE_HASH,
    SIGNER_IDENTITY,
    PACKAGE_IDENTITY,
    SIGNATURE_RULE,
    MANIFEST,
    DEX,
    NETWORK,
    PACKER,
    REPUTATION,
    IMPERSONATION,
    STATIC_BEHAVIOR,
    LOCAL_MODEL,
    CLOUD_REPUTATION,
    USER_ALLOWLIST,
    THREAT_GRAPH,
    ZERO_DAY_HEURISTIC
}

enum class FindingConfidence(val rank: Int) {
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    CONFIRMED(4)
}

enum class DetectionVerdictLevel {
    LOW,
    REVIEW,
    HIGH,
    VERY_HIGH,
    KNOWN_THREAT,
    TEST
}

data class DetectionFinding(
    val id: String,
    val source: DetectionSource,
    val score: Int,
    val confidence: FindingConfidence,
    val family: ThreatFamily = ThreatFamily.UNKNOWN,
    val reference: String? = null
)

data class MultiEngineVerdict(
    val score: Int,
    val level: DetectionVerdictLevel,
    val family: ThreatFamily,
    val confidence: FindingConfidence,
    val findings: List<DetectionFinding>,
    val engineCount: Int,
    val confirmedReference: String? = null,
    val allowlisted: Boolean = false
)

data class DetectionRule(
    val id: String,
    val family: ThreatFamily,
    val confidence: FindingConfidence,
    val weight: Int,
    val allMarkers: Set<String>,
    val anyMarkers: Set<String>,
    val notMarkers: Set<String> = emptySet()
)

data class ProtectedBrandProfile(
    val id: String,
    val officialPackage: String,
    val tokens: Set<String>,
    val trustedSignerSha256: Set<String> = emptySet()
)

enum class ReputationKind {
    FILE,
    SIGNER,
    PACKAGE,
    HOST
}

enum class ReputationDisposition {
    MALICIOUS,
    SAFE,
    TEST
}


enum class ThreatGraphRelation {
    SAME_SIGNER,
    SAME_PACKAGE,
    SAME_CAMPAIGN,
    CONTACTS_HOST,
    DROPS_PAYLOAD,
    REVIEWED_ASSOCIATION
}

data class ThreatGraphLink(
    val fromId: String,
    val toId: String,
    val relation: ThreatGraphRelation,
    val confidence: FindingConfidence,
    val weight: Int
)

data class ReputationIndicator(
    val kind: ReputationKind,
    val sha256: String,
    val id: String,
    val family: ThreatFamily,
    val confidence: FindingConfidence,
    val disposition: ReputationDisposition
)


data class ThreatIntelMetadata(
    val id: String,
    val source: String,
    val family: ThreatFamily,
    val confidence: FindingConfidence,
    val firstSeen: String? = null,
    val lastSeen: String? = null
)


data class ZeroDayProfile(
    val signals: Set<com.aman.security.scanner.ApkRiskSignal>,
    val markers: Set<String>,
    val hiddenDexPayloadCount: Int = 0,
    val hiddenElfPayloadCount: Int = 0,
    val nestedArchivePayloadCount: Int = 0,
    val highEntropyAssetCount: Int = 0,
    val dexFileCount: Int = 0,
    val nativeLibraryCount: Int = 0,
    val codeScanTruncated: Boolean = false
)

data class DetectionRuleset(
    val rules: List<DetectionRule> = emptyList(),
    val brands: List<ProtectedBrandProfile> = emptyList(),
    val modelWeights: Map<String, Double> = emptyMap(),
    val reasoningWeights: Map<String, Double> = emptyMap(),
    val reputation: Map<String, ReputationIndicator> = emptyMap(),
    val metadata: Map<String, ThreatIntelMetadata> = emptyMap(),
    val graphLinks: List<ThreatGraphLink> = emptyList()
) {
    fun findReputation(kind: ReputationKind, sha256: String): ReputationIndicator? =
        reputation["$kind:${sha256.lowercase()}"]

    fun findMetadata(id: String): ThreatIntelMetadata? = metadata[id]

    fun trustedSignerHashesForBrand(brandId: String): Set<String> =
        brands.firstOrNull { it.id == brandId }?.trustedSignerSha256.orEmpty()
}
