package com.aman.security.autonomous

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutonomousThreatParsersTest {
    @Test fun extractsOnlyMalwareBazaarSampleLinks() {
        val h = "a".repeat(64)
        val text = "<a href=\"/sample/$h/\">$h</a> " + "b".repeat(64)
        assertEquals(setOf(h), AutonomousThreatParsers.malwareBazaarAndroidHashes(text))
    }

    @Test fun normalizesPhishingDomains() {
        val result = AutonomousThreatParsers.phishingHosts("[\"Bad-Login.Example\",\"wallet-check.test\"]")
        assertTrue("bad-login.example" in result)
        assertTrue("wallet-check.test" in result)
    }

    @Test fun parsesUrlhausMalwareHosts() {
        val text = """
            # URLhaus list
            https://bad.example/payload.apk
            http://192.0.2.8/dropper
            not-a-url
        """.trimIndent()
        val result = AutonomousThreatParsers.urlhausHosts(text)
        assertTrue("bad.example" in result)
        assertTrue("192.0.2.8" in result)
        assertEquals(2, result.size)
    }

    @Test fun validatesFeodoIps() {
        val text = "[{\"ip_address\":\"192.0.2.7\"},{\"ip_address\":\"999.0.0.1\"}]"
        assertEquals(setOf("192.0.2.7"), AutonomousThreatParsers.feodoIps(text))
    }

    @Test fun findsLatestPatchAndCves() {
        val text = "2026-07-05 2026-08-01 2026-08-05 CVE-2026-12345 CVE-2026-12345 CVE-2026-54321"
        assertEquals("2026-08-05", AutonomousThreatParsers.latestAndroidPatch(text))
        assertEquals(2, AutonomousThreatParsers.cves(text).size)
    }

    @Test fun sourcePolicyRejectsUnknownHostsAndExecutablePayloads() {
        assertTrue(AutonomousSourcePolicy.allowed("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"))
        assertTrue(AutonomousSourcePolicy.allowed("https://urlhaus.abuse.ch/downloads/text/"))
        assertFalse(AutonomousSourcePolicy.allowed("https://evil.example/downloads/ipblocklist_recommended.json"))
        assertFalse(AutonomousSourcePolicy.allowed("https://api.destroy.tools/v1/feed/primary_active?redirect=evil"))
        assertFalse(AutonomousSourcePolicy.textPayloadAllowed(byteArrayOf(0x50,0x4b,0x03,0x04)))
        assertFalse(AutonomousSourcePolicy.textPayloadAllowed(byteArrayOf(0x64,0x65,0x78,0x0a)))
        assertTrue(AutonomousSourcePolicy.textPayloadAllowed("[]".toByteArray()))
    }
}
