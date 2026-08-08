package com.aman.security.scanner

import android.content.Context

class SignatureDatabase(private val context: Context) {
    data class Info(val version: String, val serial: Long, val entries: Int, val downloaded: Boolean)

    private val storage = ThreatDbStorage(context)
    private val bundled: ThreatDbValidator.ValidatedPackage = loadBundled()
    @Volatile private var active: ThreatDbValidator.ValidatedPackage
    @Volatile private var downloaded = false

    init {
        val installed = storage.loadInstalled()
        if (installed != null && installed.manifest.serial >= bundled.manifest.serial) {
            active = installed
            downloaded = true
        } else {
            storage.clearInvalidInstalled()
            active = bundled
        }
    }

    val info: Info
        get() = Info(active.manifest.version, active.manifest.serial, active.signatures.size, downloaded)

    fun find(sha256: String): ThreatSignature? = active.signatures[sha256.lowercase()]

    @Synchronized
    fun reloadAfterUpdate() {
        val installed = storage.loadInstalled() ?: return
        if (installed.manifest.serial >= active.manifest.serial && installed.manifest.serial >= bundled.manifest.serial) {
            active = installed
            downloaded = true
        }
    }

    private fun loadBundled(): ThreatDbValidator.ValidatedPackage {
        val manifest = context.assets.open("threat-db/manifest.json").use { it.readBytes() }
        val signature = context.assets.open("threat-db/manifest.sig").use { it.readBytes() }
        val database = context.assets.open("threat-db/signatures.csv").use { it.readBytes() }
        return ThreatDbValidator.validate(context, manifest, signature, database)
    }
}
