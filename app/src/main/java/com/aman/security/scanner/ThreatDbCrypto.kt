package com.aman.security.scanner

import android.content.Context
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

object ThreatDbCrypto {
    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    fun verifyManifest(context: Context, manifestBytes: ByteArray, signatureBytes: ByteArray): Boolean {
        val pem = context.assets.open("keys/threat_update_public_key.pem")
            .bufferedReader()
            .use { it.readText() }
        val body = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(Regex("\\s"), "")
        val keyBytes = Base64.getDecoder().decode(body)
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyBytes))
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(publicKey)
        verifier.update(manifestBytes)
        return verifier.verify(signatureBytes)
    }
}
