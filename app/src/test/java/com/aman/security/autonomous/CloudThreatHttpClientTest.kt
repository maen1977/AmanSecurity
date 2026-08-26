package com.aman.security.autonomous

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudThreatHttpClientTest {
    @Test fun acceptsOnlyExpectedPublicThreatRepoRawBranchShape() {
        assertTrue(CloudThreatHttpClient.validateBase(
            "https://raw.githubusercontent.com/maen1977/AmanSecurity/aman-threat-db/latest"
        ))
        assertFalse(CloudThreatHttpClient.validateBase("http://raw.githubusercontent.com/maen1977/AmanSecurity-Threat-DB/main/latest"))
        assertFalse(CloudThreatHttpClient.validateBase("https://evil.example/maen1977/AmanSecurity-Threat-DB/main/latest"))
        assertFalse(CloudThreatHttpClient.validateBase("https://raw.githubusercontent.com/maen1977/AmanSecurity/main/latest"))
        assertFalse(CloudThreatHttpClient.validateBase("https://raw.githubusercontent.com/maen1977/AmanSecurity-Threat-DB/main/latest"))
        assertFalse(CloudThreatHttpClient.validateBase("https://raw.githubusercontent.com/maen1977/AmanSecurity/aman-threat-db/latest?x=1"))
    }
}
