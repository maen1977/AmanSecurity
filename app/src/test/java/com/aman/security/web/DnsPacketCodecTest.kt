package com.aman.security.web

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DnsPacketCodecTest {
    @Test
    fun parsesDnsHostAndBuildsNxdomainResponse() {
        val dns = dnsQuery("malware.example")
        val packet = ipv4UdpPacket(dns)
        val parsed = DnsPacketCodec.parseIpv4UdpDns(packet, packet.size)
        assertNotNull(parsed)
        assertEquals("malware.example", parsed!!.host)
        assertEquals(53, parsed.destinationPort)

        val denied = DnsPacketCodec.nxdomainResponse(parsed.dnsPayload)
        assertTrue((denied[2].toInt() and 0x80) != 0)
        assertEquals(3, denied[3].toInt() and 0x0f)

        val response = DnsPacketCodec.buildIpv4UdpResponse(parsed, denied)
        val responseSource = InetAddress.getByAddress(response.copyOfRange(12, 16)).hostAddress
        val responseDestination = InetAddress.getByAddress(response.copyOfRange(16, 20)).hostAddress
        assertEquals("10.73.0.2", responseSource)
        assertEquals("10.73.0.1", responseDestination)
    }

    @Test
    fun malformedOrNonDnsPacketsAreRejected() {
        assertEquals(null, DnsPacketCodec.parseIpv4UdpDns(ByteArray(5), 5))
        val tcp = ipv4UdpPacket(dnsQuery("example.org")).also { it[9] = 6 }
        assertEquals(null, DnsPacketCodec.parseIpv4UdpDns(tcp, tcp.size))
    }

    private fun dnsQuery(host: String): ByteArray {
        val labels = host.split('.')
        val out = ArrayList<Byte>()
        fun short(value: Int) {
            out += ((value ushr 8) and 0xff).toByte()
            out += (value and 0xff).toByte()
        }
        short(0x1234)
        short(0x0100)
        short(1)
        short(0)
        short(0)
        short(0)
        labels.forEach { label ->
            out += label.length.toByte()
            label.toByteArray(Charsets.US_ASCII).forEach(out::add)
        }
        out += 0
        short(1)
        short(1)
        return out.toByteArray()
    }

    private fun ipv4UdpPacket(dns: ByteArray): ByteArray {
        val total = 20 + 8 + dns.size
        return ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN).apply {
            put(0x45.toByte())
            put(0)
            putShort(total.toShort())
            putShort(1)
            putShort(0)
            put(64)
            put(17)
            putShort(0)
            put(byteArrayOf(10, 73, 0, 1))
            put(byteArrayOf(10, 73, 0, 2))
            putShort(53000.toShort())
            putShort(53)
            putShort((8 + dns.size).toShort())
            putShort(0)
            put(dns)
        }.array()
    }
}
