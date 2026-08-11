package com.aman.security.scanner

import java.io.InputStream
import java.security.MessageDigest

object Sha256 {
    fun fromStream(input: InputStream, onBytesRead: ((Long) -> Unit)? = null): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var totalRead = 0L
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
            totalRead += read
            onBytesRead?.invoke(totalRead)
        }
        return digest.digest().joinToString(separator = "") { byte -> "%02x".format(byte) }
    }
}
