package com.aman.security.web

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ThreadLocalRandom

object WebShieldSelfTestPolicy {
    private const val SUFFIX = ".webshield-test.aman.invalid"

    fun createHost(now: Long = System.currentTimeMillis()): String =
        "${now}-${ThreadLocalRandom.current().nextInt(100000, 999999)}$SUFFIX"

    fun isSelfTestHost(host: String): Boolean {
        val normalized = host.trim().trimEnd('.').lowercase()
        return normalized.endsWith(SUFFIX) && normalized.length > SUFFIX.length
    }
}

/**
 * Sends one tiny DNS query directly to the synthetic DNS endpoint owned by the
 * local VPN. This validates the TUN route + DNS parser + test-block path without
 * contacting any external host and without running a background loop.
 */
object WebShieldSelfTestClient {
    fun run(host: String): Boolean = runCatching {
        val request = buildQuery(host)
        DatagramSocket().use { socket ->
            socket.soTimeout = 2500
            val destination = InetAddress.getByName(LocalDnsVpnService.SYNTHETIC_DNS_ADDRESS)
            socket.send(DatagramPacket(request, request.size, destination, LocalDnsVpnService.DNS_PORT_PUBLIC))
            val response = ByteArray(1024)
            val packet = DatagramPacket(response, response.size)
            socket.receive(packet)
            if (packet.length < 12) return@runCatching false
            val responseId = ((response[0].toInt() and 0xff) shl 8) or (response[1].toInt() and 0xff)
            val requestId = ((request[0].toInt() and 0xff) shl 8) or (request[1].toInt() and 0xff)
            val responseFlag = (response[2].toInt() and 0x80) != 0
            val rcode = response[3].toInt() and 0x0f
            responseId == requestId && responseFlag && rcode == 3
        }
    }.getOrDefault(false)

    private fun buildQuery(host: String): ByteArray {
        val labels = host.split('.').filter { it.isNotBlank() }
        val id = ThreadLocalRandom.current().nextInt(0, 65536)
        val bytes = ArrayList<Byte>(64)
        fun add(value: Int) { bytes += (value and 0xff).toByte() }
        add(id ushr 8); add(id)
        add(0x01); add(0x00) // recursion desired
        add(0x00); add(0x01) // one question
        repeat(6) { add(0x00) }
        labels.forEach { label ->
            val encoded = label.toByteArray(Charsets.US_ASCII)
            require(encoded.size in 1..63)
            add(encoded.size)
            encoded.forEach { bytes += it }
        }
        add(0x00)
        add(0x00); add(0x01) // A
        add(0x00); add(0x01) // IN
        return ByteArray(bytes.size) { index -> bytes[index] }
    }
}
