package com.aman.security.autonomous

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudThreatHttpClientTest {
    @Test fun acceptsOnlyExpectedGithubRawBranchShape() {
        assertTrue(CloudThreatHttpClient.validateBase(
            "https://raw.githubusercontent.com/example/aman/aman-threat-db/latest"
        ))
        assertFalse(CloudThreatHttpClient.validateBase("http://raw.githubusercontent.com/example/aman/aman-threat-db/latest"))
        assertFalse(CloudThreatHttpClient.validateBase("https://evil.example/example/aman/aman-threat-db/latest"))
        assertFalse(CloudThreatHttpClient.validateBase("https://raw.githubusercontent.com/example/aman/main/latest"))
        assertFalse(CloudThreatHttpClient.validateBase("https://raw.githubusercontent.com/example/aman/aman-threat-db/latest?x=1"))
    }
}
