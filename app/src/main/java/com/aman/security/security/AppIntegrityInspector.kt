package com.aman.security.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.aman.security.BuildConfig
import java.security.MessageDigest
import java.util.Locale

enum class AppIntegrityStatus {
    DEBUG_BUILD,
    VERIFIED_RELEASE,
    UNPINNED_RELEASE,
    SIGNATURE_MISMATCH,
    UNKNOWN
}

data class AppIntegritySnapshot(
    val status: AppIntegrityStatus,
    val signerSha256: String?,
    val expectedSignerSha256: String?
)

/**
 * Local self-integrity signal. The expected release certificate SHA-256 is public metadata,
 * not a secret. Production distributors can provide it as the Gradle property
 * AMAN_RELEASE_CERT_SHA256. Debug builds intentionally report DEBUG_BUILD.
 */
object AppIntegrityInspector {
    fun inspect(context: Context): AppIntegritySnapshot {
        val expected = BuildConfig.EXPECTED_RELEASE_CERT_SHA256
            .trim().lowercase(Locale.ROOT).takeIf { SHA256.matches(it) }
        val signer = currentSignerSha256(context)
        val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 || BuildConfig.DEBUG

        val status = when {
            debuggable -> AppIntegrityStatus.DEBUG_BUILD
            signer == null -> AppIntegrityStatus.UNKNOWN
            expected == null -> AppIntegrityStatus.UNPINNED_RELEASE
            signer.equals(expected, ignoreCase = true) -> AppIntegrityStatus.VERIFIED_RELEASE
            else -> AppIntegrityStatus.SIGNATURE_MISMATCH
        }
        return AppIntegritySnapshot(status, signer, expected)
    }

    private fun currentSignerSha256(context: Context): String? = runCatching {
        val pm = context.packageManager
        val signingFlag = signingInfoFlag()
        val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(
                context.packageName,
                PackageManager.PackageInfoFlags.of(signingFlag.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, signingFlag)
        }
        val signingInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) packageInfo.signingInfo else null
        val bytes = if (signingInfo != null) {
            val signers = if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners else signingInfo.signingCertificateHistory
            signers.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures?.firstOrNull()?.toByteArray()
        } ?: throw IllegalStateException("Signer unavailable")
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }.getOrNull()

    @Suppress("DEPRECATION")
    private fun signingInfoFlag(): Int = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        PackageManager.GET_SIGNING_CERTIFICATES
    } else {
        PackageManager.GET_SIGNATURES
    }

    private val SHA256 = Regex("^[a-f0-9]{64}$")
}
