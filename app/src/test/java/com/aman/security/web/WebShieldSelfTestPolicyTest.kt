package com.aman.security.web

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WebShieldSelfTestPolicyTest {
    @Test fun generatedHostIsRecognized() {
        assertTrue(WebShieldSelfTestPolicy.isSelfTestHost(WebShieldSelfTestPolicy.createHost(123456L)))
    }

    @Test fun ordinaryHostsAreNeverTreatedAsSelfTest() {
        assertFalse(WebShieldSelfTestPolicy.isSelfTestHost("www.amtso.org"))
        assertFalse(WebShieldSelfTestPolicy.isSelfTestHost("example.com"))
    }
}
