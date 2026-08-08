package com.aman.security.scanner

import android.content.Context
import java.io.File

class ThreatDbStorage(private val context: Context) {
    private val root = File(context.filesDir, "threat-db")
    private val packages = File(root, "packages")
    private val activePointer = File(root, "active_serial")

    fun loadInstalled(): ThreatDbValidator.ValidatedPackage? {
        val preferred = activePointer.takeIf { it.isFile }
            ?.readText()
            ?.trim()
            ?.toLongOrNull()
            ?.let(::loadPackage)
        if (preferred != null) return preferred

        val fallback = packages.listFiles()
            ?.filter { it.isDirectory && it.name.toLongOrNull() != null }
            ?.sortedByDescending { it.name.toLong() }
            ?.firstNotNullOfOrNull { loadPackage(it.name.toLong()) }
        if (fallback != null) writePointer(fallback.manifest.serial)
        return fallback
    }

    fun install(manifestBytes: ByteArray, signatureBytes: ByteArray, databaseBytes: ByteArray) {
        val validated = ThreatDbValidator.validate(context, manifestBytes, signatureBytes, databaseBytes)
        val serial = validated.manifest.serial
        val finalDir = File(packages, serial.toString())
        val staging = File(packages, ".staging-$serial")

        root.mkdirs()
        packages.mkdirs()
        staging.deleteRecursively()
        staging.mkdirs()
        File(staging, "manifest.json").writeBytes(manifestBytes)
        File(staging, "manifest.sig").writeBytes(signatureBytes)
        File(staging, "signatures.csv").writeBytes(databaseBytes)

        val staged = loadFromDirectory(staging) ?: run {
            staging.deleteRecursively()
            throw IllegalStateException()
        }
        require(staged.manifest.serial == serial)

        finalDir.deleteRecursively()
        if (!staging.renameTo(finalDir)) {
            staging.deleteRecursively()
            throw IllegalStateException()
        }
        require(loadPackage(serial) != null)
        writePointer(serial)
        pruneOldPackages(keep = 3)
    }

    fun clearInvalidInstalled() {
        packages.listFiles()?.forEach { dir ->
            if (dir.isDirectory && !dir.name.startsWith(".staging-") && loadFromDirectory(dir) == null) {
                dir.deleteRecursively()
            }
            if (dir.isDirectory && dir.name.startsWith(".staging-")) dir.deleteRecursively()
        }
    }

    private fun loadPackage(serial: Long): ThreatDbValidator.ValidatedPackage? =
        loadFromDirectory(File(packages, serial.toString()))

    private fun loadFromDirectory(dir: File): ThreatDbValidator.ValidatedPackage? {
        val manifest = File(dir, "manifest.json")
        val signature = File(dir, "manifest.sig")
        val database = File(dir, "signatures.csv")
        if (!manifest.isFile || !signature.isFile || !database.isFile) return null
        return runCatching {
            ThreatDbValidator.validate(context, manifest.readBytes(), signature.readBytes(), database.readBytes())
        }.getOrNull()
    }

    private fun writePointer(serial: Long) {
        root.mkdirs()
        val temp = File(root, "active_serial.new")
        temp.writeText(serial.toString())
        if (activePointer.exists() && !activePointer.delete()) {
            temp.delete()
            throw IllegalStateException()
        }
        if (!temp.renameTo(activePointer)) {
            temp.delete()
            throw IllegalStateException()
        }
    }

    private fun pruneOldPackages(keep: Int) {
        packages.listFiles()
            ?.filter { it.isDirectory && it.name.toLongOrNull() != null }
            ?.sortedByDescending { it.name.toLong() }
            ?.drop(keep)
            ?.forEach { it.deleteRecursively() }
    }
}
