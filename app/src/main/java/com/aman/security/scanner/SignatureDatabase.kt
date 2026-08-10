package com.aman.security.scanner

import android.content.Context
import com.aman.security.autonomous.AutonomousThreatStore
import com.aman.security.detection.DetectionRuleset
import com.aman.security.detection.ReputationIndicator
import com.aman.security.detection.ReputationKind

class SignatureDatabase(private val context: Context) {
    data class Info(
        val version: String,
        val serial: Long,
        val fileEntries: Int,
        val urlEntries: Int,
        val apkIdentityEntries: Int,
        val detectionEntries: Int,
        val generatedAt: String,
        val downloaded: Boolean = false
    ) { val entries: Int get() = fileEntries + urlEntries + apkIdentityEntries + detectionEntries }

    private val bundled: ThreatDbValidator.ValidatedPackage = loadBundled()
    val autonomousStore = AutonomousThreatStore(context)

    val info: Info get() = Info(
        version = bundled.manifest.version,
        serial = bundled.manifest.serial,
        fileEntries = bundled.signatures.size,
        urlEntries = bundled.urlIndicators.size,
        apkIdentityEntries = bundled.apkIdentityIndicators.size,
        detectionEntries = bundled.manifest.detectionEntries,
        generatedAt = bundled.manifest.generatedAt
    )

    val detectionRuleset: DetectionRuleset get() = bundled.detectionRuleset

    fun find(sha256: String): ThreatSignature? = autonomousStore.findFile(sha256) ?: bundled.signatures[sha256.lowercase()]
    fun findUrl(kind: UrlIndicatorKind, sha256: String): UrlThreatIndicator? = autonomousStore.findUrl(kind, sha256) ?: bundled.urlIndicators["$kind:${sha256.lowercase()}"]
    fun findApk(kind: ApkIndicatorKind, sha256: String): ApkIdentityIndicator? = bundled.apkIdentityIndicators["$kind:${sha256.lowercase()}"]
    fun findReputation(kind: ReputationKind, sha256: String): ReputationIndicator? = bundled.detectionRuleset.findReputation(kind, sha256)
    fun canaryHealthy(): Boolean = ThreatDbCanary.valid(bundled.signatures.values)
    @Synchronized fun reloadAutonomous() = autonomousStore.reload()

    private fun loadBundled(): ThreatDbValidator.ValidatedPackage {
        val manifest = context.assets.open("threat-db/manifest.json").use { it.readBytes() }
        val database = context.assets.open("threat-db/signatures.csv").use { it.readBytes() }
        val parsedManifest = ThreatDbManifest.parse(manifest)
        val urls = if (parsedManifest.schema >= 2) context.assets.open("threat-db/url_indicators.csv").use { it.readBytes() } else null
        val apkIdentities = if (parsedManifest.schema >= 3) context.assets.open("threat-db/apk_indicators.csv").use { it.readBytes() } else null
        val detection = if (parsedManifest.schema >= 4) context.assets.open("threat-db/detection_rules.csv").use { it.readBytes() } else null
        return ThreatDbValidator.validate(manifest, database, urls, apkIdentities, detection)
    }
}
