package com.aman.security.protection

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FindingNotificationGateTest {
    @Test
    fun `same finding is suppressed during cooldown and allowed afterwards`() {
        val gate = FindingNotificationGate(cooldownMs = 60_000L)

        assertTrue(gate.shouldNotify("hidden:com.example.app", 1_000L))
        assertFalse(gate.shouldNotify("hidden:com.example.app", 30_000L))
        assertTrue(gate.shouldNotify("hidden:com.example.app", 61_000L))
    }

    @Test
    fun `different findings are independently eligible`() {
        val gate = FindingNotificationGate(cooldownMs = 60_000L)

        assertTrue(gate.shouldNotify("hidden:com.example.one", 1_000L))
        assertTrue(gate.shouldNotify("hidden:com.example.two", 1_000L))
        assertFalse(gate.shouldNotify("hidden:com.example.one", 2_000L))
    }

    @Test
    fun `blank keys never notify`() {
        val gate = FindingNotificationGate(cooldownMs = 60_000L)

        assertFalse(gate.shouldNotify("", 1_000L))
        assertFalse(gate.shouldNotify("   ", 2_000L))
    }
}
