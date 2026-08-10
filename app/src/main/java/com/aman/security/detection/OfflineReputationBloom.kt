package com.aman.security.detection

import android.content.Context
import android.util.Base64
import com.aman.security.scanner.ThreatDbCrypto
import org.json.JSONObject
import java.security.MessageDigest

/** Signed low-memory prefilter for malicious file hashes. A hit is never treated
 * as a known threat because Bloom filters can have false positives. */
class OfflineReputationBloom(private val context: Context) {
    private data class State(val bitCount: Int, val hashes: Int, val salt: String, val bits: ByteArray)
    private val state: State? by lazy { load() }

    fun mightContain(sha256: String): Boolean {
        val st = state ?: return false
        val normalized = sha256.lowercase()
        if (!normalized.matches(Regex("^[a-f0-9]{64}$"))) return false
        repeat(st.hashes) { i ->
            val digest = MessageDigest.getInstance("SHA-256")
                .digest((st.salt + ":" + i + ":" + normalized).toByteArray(Charsets.UTF_8))
            val bit = ((longAt(digest, 0) and Long.MAX_VALUE) % st.bitCount.toLong()).toInt()
            if ((st.bits[bit ushr 3].toInt() and (1 shl (bit and 7))) == 0) return false
        }
        return true
    }

    private fun load(): State? = runCatching {
        val data = context.assets.open("reputation/file_bloom.json").use { it.readBytes() }
        val sig = context.assets.open("reputation/file_bloom.sig").use { it.readBytes() }
        require(ThreatDbCrypto.verifyDetached(context, data, sig))
        val json = JSONObject(data.toString(Charsets.UTF_8))
        require(json.getInt("schema") == 1)
        val bitCount = json.getInt("bitCount").also { require(it in 1024..16_777_216) }
        val hashes = json.getInt("hashFunctions").also { require(it in 1..12) }
        val salt = json.getString("salt").also { require(it.length in 1..64) }
        val bits = Base64.decode(json.getString("bitsBase64"), Base64.DEFAULT)
        require(bits.size * 8 >= bitCount)
        State(bitCount, hashes, salt, bits)
    }.getOrNull()

    private fun longAt(bytes: ByteArray, offset: Int): Long {
        var value = 0L
        repeat(8) { value = (value shl 8) or (bytes[offset + it].toLong() and 0xff) }
        return value
    }
}
