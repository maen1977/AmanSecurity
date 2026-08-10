package com.aman.security.scanner

import android.content.Context
import com.aman.security.detection.DetectionRuleset
import com.aman.security.detection.ReputationIndicator
import com.aman.security.detection.ReputationKind
import com.aman.security.detection.OfflineReputationBloom

class SignatureDatabase(private val context: Context) {
    data class Info(
        val version: String,
        val serial: Long,
        val fileEntries: Int,
        val urlEntries: Int,
        val apkIdentityEntries: Int,
        val detectionEntries: Int,
        val generatedAt: String,
        val downloaded: Boolean
    ) {
        val entries: Int get() = fileEntries + urlEntries + apkIdentityEntries + detectionEntries
    }

    private val storage = ThreatDbStorage(context)
    private val offlineBloom = OfflineReputationBloom(context)
    private val bundled: ThreatDbValidator.ValidatedPackage = loadBundled()
    @Volatile private var active: ThreatDbValidator.ValidatedPackage
    @Volatile private var downloaded = false

    init {
        val installed = storage.loadInstalled()
        if (installed != null && installed.manifest.schema >= bundled.manifest.schema && installed.manifest.serial >= bundled.manifest.serial) {
            active = installed; downloaded = true
        } else {
            storage.clearInvalidInstalled(); active = bundled
        }
    }

    val info: Info
        get() = Info(
            version = active.manifest.version,
            serial = active.manifest.serial,
            fileEntries = active.signatures.size,
            urlEntries = active.urlIndicators.size,
            apkIdentityEntries = active.apkIdentityIndicators.size,
            detectionEntries = active.manifest.detectionEntries,
            generatedAt = active.manifest.generatedAt,
            downloaded = downloaded
        )

    val detectionRuleset: DetectionRuleset get() = active.detectionRuleset

    fun find(sha256: String): ThreatSignature? = active.signatures[sha256.lowercase()]

    fun findUrl(kind: UrlIndicatorKind, sha256: String): UrlThreatIndicator? = active.urlIndicators["$kind:${sha256.lowercase()}"]

    fun findApk(kind: ApkIndicatorKind, sha256: String): ApkIdentityIndicator? = active.apkIdentityIndicators["$kind:${sha256.lowercase()}"]

    fun findReputation(kind: ReputationKind, sha256: String): ReputationIndicator? = active.detectionRuleset.findReputation(kind, sha256)

    fun mightContainMaliciousFileHash(sha256: String): Boolean = offlineBloom.mightContain(sha256)

    fun canaryHealthy(): Boolean = ThreatDbCanary.valid(active.signatures.values)

    @Synchronized
    fun reloadAfterUpdate() {
        val installed = storage.loadInstalled() ?: return
        if (installed.manifest.schema >= bundled.manifest.schema && installed.manifest.serial >= active.manifest.serial && installed.manifest.serial >= bundled.manifest.serial) {
            active = installed; downloaded = true
        }
    }

    private fun loadBundled(): ThreatDbValidator.ValidatedPackage {
        val manifest = context.assets.open("threat-db/manifest.json").use { it.readBytes() }
        val signature = context.assets.open("threat-db/manifest.sig").use { it.readBytes() }
        val database = context.assets.open("threat-db/signatures.csv").use { it.readBytes() }
        val parsedManifest = ThreatDbManifest.parse(manifest)
        val urls = if (parsedManifest.schema >= 2) context.assets.open("threat-db/url_indicators.csv").use { it.readBytes() } else null
        val apkIdentities = if (parsedManifest.schema >= 3) context.assets.open("threat-db/apk_indicators.csv").use { it.readBytes() } else null
        val detection = if (parsedManifest.schema >= 4) context.assets.open("threat-db/detection_rules.csv").use { it.readBytes() } else null
        return ThreatDbValidator.validate(context, manifest, signature, database, urls, apkIdentities, detection)
    }
}
