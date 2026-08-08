package com.aman.security.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class QuarantineCrypto {
    fun encrypt(input: InputStream, output: OutputStream, onPlainChunk: (ByteArray, Int) -> Unit) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val iv = cipher.iv
        output.write(MAGIC)
        output.write(iv.size)
        output.write(iv)
        CipherOutputStream(output, cipher).use { encrypted ->
            copy(input, encrypted, onPlainChunk)
        }
    }

    fun decrypt(input: InputStream, output: OutputStream, onPlainChunk: (ByteArray, Int) -> Unit) {
        val magic = ByteArray(MAGIC.size)
        readFully(input, magic)
        require(magic.contentEquals(MAGIC))
        val ivLength = input.read()
        require(ivLength in 12..32)
        val iv = ByteArray(ivLength)
        readFully(input, iv)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        CipherInputStream(input, cipher).use { decrypted ->
            copy(decrypted, output, onPlainChunk)
        }
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            generateKey()
        }
    }

    private fun readFully(input: InputStream, target: ByteArray) {
        var offset = 0
        while (offset < target.size) {
            val read = input.read(target, offset, target.size - offset)
            require(read > 0)
            offset += read
        }
    }

    private fun copy(input: InputStream, output: OutputStream, onChunk: (ByteArray, Int) -> Unit) {
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            if (read == 0) continue
            onChunk(buffer, read)
            output.write(buffer, 0, read)
        }
        output.flush()
    }

    companion object {
        private val MAGIC = byteArrayOf('A'.code.toByte(), 'M'.code.toByte(), 'Q'.code.toByte(), '1'.code.toByte())
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "aman_quarantine_aes_v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
