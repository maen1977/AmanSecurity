package com.aman.security.web

import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Minimal IPv4/UDP/DNS codec for the local DNS-only VPN shield. */
data class DnsQueryPacket(
    val sourceAddress: InetAddress,
    val destinationAddress: InetAddress,
    val sourcePort: Int,
    val destinationPort: Int,
    val dnsPayload: ByteArray,
    val host: String?
)

object DnsPacketCodec {
    fun parseIpv4UdpDns(packet: ByteArray, length: Int): DnsQueryPacket? {
        if (length < 20 || packet.isEmpty()) return null
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl + 8) return null
        val protocol = packet[9].toInt() and 0xff
        if (protocol != 17) return null
        val source = InetAddress.getByAddress(packet.copyOfRange(12, 16))
        val destination = InetAddress.getByAddress(packet.copyOfRange(16, 20))
        val udp = ByteBuffer.wrap(packet, ihl, length - ihl).order(ByteOrder.BIG_ENDIAN)
        val sourcePort = udp.short.toInt() and 0xffff
        val destinationPort = udp.short.toInt() and 0xffff
        val udpLength = udp.short.toInt() and 0xffff
        udp.short // checksum
        val payloadLength = (udpLength - 8).coerceAtMost(length - ihl - 8)
        if (payloadLength < 12) return null
        val payload = packet.copyOfRange(ihl + 8, ihl + 8 + payloadLength)
        return DnsQueryPacket(
            sourceAddress = source,
            destinationAddress = destination,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsPayload = payload,
            host = parseQuestionHost(payload)
        )
    }

    fun nxdomainResponse(query: ByteArray): ByteArray {
        if (query.size < 12) return query.copyOf()
        val response = query.copyOf()
        // QR=1, RD preserved, RA=1, RCODE=3 (NXDOMAIN).
        val requestFlags = ((query[2].toInt() and 0xff) shl 8) or (query[3].toInt() and 0xff)
        val flags = 0x8000 or 0x0080 or (requestFlags and 0x0100) or 0x0003
        response[2] = ((flags ushr 8) and 0xff).toByte()
        response[3] = (flags and 0xff).toByte()
        // Answer/authority/additional counts are zero. Keep the original question count.
        for (index in 6..11) response[index] = 0
        return response
    }

    fun servFailResponse(query: ByteArray): ByteArray {
        if (query.size < 12) return query.copyOf()
        val response = query.copyOf()
        val requestFlags = ((query[2].toInt() and 0xff) shl 8) or (query[3].toInt() and 0xff)
        val flags = 0x8000 or 0x0080 or (requestFlags and 0x0100) or 0x0002
        response[2] = ((flags ushr 8) and 0xff).toByte()
        response[3] = (flags and 0xff).toByte()
        for (index in 6..11) response[index] = 0
        return response
    }

    fun buildIpv4UdpResponse(query: DnsQueryPacket, dnsPayload: ByteArray): ByteArray {
        val totalLength = 20 + 8 + dnsPayload.size
        val buffer = ByteBuffer.allocate(totalLength).order(ByteOrder.BIG_ENDIAN)
        buffer.put(0x45.toByte()) // IPv4, IHL=5
        buffer.put(0) // DSCP/ECN
        buffer.putShort(totalLength.toShort())
        buffer.putShort(0) // ID
        buffer.putShort(0) // flags/fragment offset
        buffer.put(64.toByte()) // TTL
        buffer.put(17.toByte()) // UDP
        buffer.putShort(0) // header checksum, filled below
        buffer.put(query.destinationAddress.address)
        buffer.put(query.sourceAddress.address)
        buffer.putShort(query.destinationPort.toShort())
        buffer.putShort(query.sourcePort.toShort())
        buffer.putShort((8 + dnsPayload.size).toShort())
        buffer.putShort(0) // UDP checksum 0 is valid for IPv4
        buffer.put(dnsPayload)
        val bytes = buffer.array()
        val checksum = ipv4HeaderChecksum(bytes)
        bytes[10] = ((checksum ushr 8) and 0xff).toByte()
        bytes[11] = (checksum and 0xff).toByte()
        return bytes
    }

    private fun parseQuestionHost(payload: ByteArray): String? {
        if (payload.size < 13) return null
        val questionCount = ((payload[4].toInt() and 0xff) shl 8) or (payload[5].toInt() and 0xff)
        if (questionCount < 1) return null
        var offset = 12
        val labels = mutableListOf<String>()
        while (offset < payload.size) {
            val size = payload[offset].toInt() and 0xff
            offset++
            if (size == 0) break
            // Compression pointers are not expected in normal DNS questions; skip rather than misparse.
            if (size and 0xc0 != 0 || size > 63 || offset + size > payload.size) return null
            val label = payload.copyOfRange(offset, offset + size).toString(Charsets.UTF_8)
            if (label.isBlank()) return null
            labels += label
            offset += size
        }
        return labels.takeIf { it.isNotEmpty() }?.joinToString(".")?.trimEnd('.')?.lowercase()
    }

    private fun ipv4HeaderChecksum(packet: ByteArray): Int {
        var sum = 0L
        var index = 0
        while (index < 20) {
            if (index == 10) {
                index += 2
                continue
            }
            sum += (((packet[index].toInt() and 0xff) shl 8) or (packet[index + 1].toInt() and 0xff)).toLong()
            while (sum > 0xffff) sum = (sum and 0xffff) + (sum ushr 16)
            index += 2
        }
        return sum.inv().toInt() and 0xffff
    }

    fun isIpv4(address: InetAddress?): Boolean = address is Inet4Address
}
