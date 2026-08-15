package com.aman.security.web

import android.content.Intent
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WebGuardEvidencePolicyTest {
    @Test
    fun normalViewIntentProvesExternalLinkInterception() {
        assertTrue(WebGuardEvidencePolicy.provesExternalLinkInterception(Intent.ACTION_VIEW))
    }

    @Test
    fun sharedOrSelectedTextDoesNotProveBrowserRoleInterception() {
        assertFalse(WebGuardEvidencePolicy.provesExternalLinkInterception(Intent.ACTION_SEND))
        assertFalse(WebGuardEvidencePolicy.provesExternalLinkInterception(Intent.ACTION_PROCESS_TEXT))
        assertFalse(WebGuardEvidencePolicy.provesExternalLinkInterception(null))
    }
}
