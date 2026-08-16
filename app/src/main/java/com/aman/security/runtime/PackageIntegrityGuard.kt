package com.aman.security.runtime

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import com.aman.security.protection.ProtectionPreferences

/**
 * On-device package integrity guard against trojanized (modified) apps.
 *
 * One of the most widespread Android attacks is repackaging: an attacker
 * takes a popular app, injects malicious code and re-signs it. Because
 * the signature changes, comparing the signing certificate of a freshly
 * installed package against the previously seen fingerprint for the same
 * package name reliably flags modified or rogue copies.
 *
 * Fingerprints are kept in the local app-ledger store only. Fully
 * on-device, no network, no paid API.
 */
internal class PackageIntegrityGuard(private val context: Context) {

    private val preferences = ProtectionPreferences(context)

    /**
     * Verify a package's signing certificate against the last seen
     * fingerprint. Returns null when nothing suspicious was found.
     */
    fun verify(packageName: String): PackageIntegrityVerdict? = runCatching {
        if (!preferences.enabled) return@runCatching null
        val info = context.packageManager.getPackageInfo(
            packageName,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }
        )
        val current = currentFingerprint(info) ?: return@runCatching null
        val previous = preferences.appLedger()[packageName]
        if (previous.isNullOrBlank()) {
            preferences.replaceAppFingerprint(packageName, current)
            return@runCatching null
        }
        if (current == previous) return@runCatching null
        // Signature mismatch for a package the device already trusted:
        // a modified/trojanized copy or a key-rotation event.
        PackageIntegrityVerdict(
            packageName = packageName,
            previousFingerprint = previous,
            currentFingerprint = current,
            level = if (isStoreInstalled(packageName)) IntegrityLevel.REVIEW else IntegrityLevel.MODIFIED
        )
    }.getOrDefault(null)

    private fun currentFingerprint(info: android.content.pm.PackageInfo): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val certs = info.signingInfo
            if (certs == null || !certs.hasMultipleSigners() || certs.apkContentsSigners.isNullOrEmpty()) {
                return null
            }
            fingerprintOf(certs.apkContentsSigners[0])
        } else {
            @Suppress("DEPRECATION")
            val sigs: Array<Signature>? = info.signatures
            if (sigs.isNullOrEmpty()) null else fingerprintOf(sigs[0])
        }
    }

    private fun fingerprintOf(signature: Signature): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(signature.toByteArray())
            .joinToString("") { "%02x".format(it) }

    private fun isStoreInstalled(packageName: String): Boolean = runCatching {
        val installer = context.packageManager.getInstallerPackageName(packageName)
        installer == GOOGLE_PLAY || installer == AMAZON_APPSTORE
    }.getOrDefault(false)

    companion object {
        private const val GOOGLE_PLAY = "com.android.vending"
        private const val AMAZON_APPSTORE = "com.amazon.venezia"
    }
}

internal enum class IntegrityLevel { REVIEW, MODIFIED }

internal data class PackageIntegrityVerdict(
    val packageName: String,
    val previousFingerprint: String,
    val currentFingerprint: String,
    val level: IntegrityLevel
)
