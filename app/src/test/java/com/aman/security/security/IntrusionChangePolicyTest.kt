package com.aman.security.security

import org.junit.Assert.assertEquals
import org.junit.Test

class IntrusionChangePolicyTest {
    @Test
    fun ordinarySinglePrivilegeChangeIsReviewOnly() {
        val app = PrivilegedAccessApp(
            appName = "Trusted utility",
            packageName = "example.utility",
            kinds = setOf(PrivilegedAccessKind.NOTIFICATION_LISTENER),
            systemApp = false,
            sideloaded = false
        )
        assertEquals(
            IntrusionChangeSeverity.REVIEW,
            IntrusionChangePolicy.assess(app, setOf(PrivilegedAccessKind.NOTIFICATION_LISTENER))
        )
    }

    @Test
    fun sideloadedAccessibilityEnablementIsHighSignal() {
        val app = PrivilegedAccessApp(
            appName = "Remote helper",
            packageName = "example.remote",
            kinds = setOf(PrivilegedAccessKind.ACCESSIBILITY, PrivilegedAccessKind.OVERLAY),
            systemApp = false,
            sideloaded = true
        )
        assertEquals(
            IntrusionChangeSeverity.HIGH,
            IntrusionChangePolicy.assess(app, setOf(PrivilegedAccessKind.ACCESSIBILITY))
        )
    }
}
